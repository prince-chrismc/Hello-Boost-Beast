/*

MIT License

Copyright (c) 2019 Chris McArthur, prince.chrismc(at)gmail(dot)com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include <boost/beast.hpp>
#include <iostream>

namespace ip = boost::asio::ip;		 // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;	// from <boost/asio.hpp>
namespace http = boost::beast::http; // from <boost/beast/http.hpp>

namespace my_program_state
{
	std::size_t request_count()
	{
		static std::size_t count = 0;
		return ++count;
	}

	std::time_t now()
	{
		return std::time(0);
	}
} // namespace my_program_state

class http_connection : public std::enable_shared_from_this<http_connection>
{
public:
	http_connection(tcp::socket socket, boost::asio::ssl::context& context)
    		: socket_(std::move(socket), context)
	{
	}

	// Initiate the asynchronous operations associated with the connection.
	void start()
	{
		do_handshake();
	}

private:
	boost::asio::ssl::stream<tcp::socket> socket_;	  // The socket for the currently connected client.
	boost::beast::flat_buffer buffer_{ 8192 };	  // The buffer for performing reads.
	http::request<http::dynamic_body> request_;   // The request message.
	http::response<http::dynamic_body> response_; // The response message.
	boost::asio::basic_waitable_timer<std::chrono::steady_clock> deadline_{
		socket_.get_executor().context(), std::chrono::seconds(60) }; // The timer for putting a deadline on connection processing.
	size_t remaining_{50};

void do_handshake()
  {
    auto self(shared_from_this());
    socket_.async_handshake(boost::asio::ssl::stream_base::server, 
        [self](const boost::system::error_code& error)
        {
          if (!error)
          {
            	read_request()
		check_deadline();
          }
        });
  }

	// Asynchronously receive a complete request message.
	void read_request()
	{
		auto self = shared_from_this();

		http::async_read(
			socket_,
			buffer_,
			request_,
			[self](boost::beast::error_code ec,
				std::size_t bytes_transferred) {
					boost::ignore_unused(bytes_transferred);
					if (!ec)
						self->process_request();
			});
	}

	// Determine what needs to be done with the request message.
	void process_request()
	{
		response_.version(request_.version());
		response_.keep_alive(static_cast<bool>(request_.version() % 10));

		switch (request_.method())
		{
		case http::verb::get:
			response_.result(http::status::ok);
			response_.set(http::field::server, "Beast");
			create_response();
			break;

		default:
			// We return responses indicating an error if
			// we do not recognize the request method.
			response_.result(http::status::bad_request);
			response_.set(http::field::content_type, "text/plain");
			boost::beast::ostream(response_.body())
				<< "Invalid request-method '"
				<< request_.method_string().to_string()
				<< "'";
			break;
		}

		write_response();
	}

	// Construct a response message based on the program state.
	void create_response()
	{
		response_.body().consume(response_.body().size());

		if (request_.target() == "/count")
		{
			response_.set(http::field::content_type, "text/html");
			boost::beast::ostream(response_.body())
				<< "<html>\n"
				<< "<head><title>Request count</title></head>\n"
				<< "<body>\n"
				<< "<h1>Request count</h1>\n"
				<< "<p>There have been "
				<< my_program_state::request_count()
				<< " requests so far.</p>\n"
				<< "</body>\n"
				<< "</html>\n";
		}
		else if (request_.target() == "/time")
		{
			response_.set(http::field::content_type, "text/html");
			boost::beast::ostream(response_.body())
				<< "<html>\n"
				<< "<head><title>Current time</title></head>\n"
				<< "<body>\n"
				<< "<h1>Current time</h1>\n"
				<< "<p>The current time is "
				<< my_program_state::now()
				<< " seconds since the epoch.</p>\n"
				<< "</body>\n"
				<< "</html>\n";
		}
		else
		{
			response_.result(http::status::not_found);
			response_.set(http::field::content_type, "text/plain");
			boost::beast::ostream(response_.body()) << "File not found\r\n";
		}
	}

	// Asynchronously transmit the response message.
	void write_response()
	{
		auto self = shared_from_this();

		response_.set(http::field::content_length, response_.body().size());

		if (request_.version() == 11) {
			response_.set(http::field::keep_alive, "timeout=60, max=" + std::to_string(remaining_));
		}
		else {
			response_.set(http::field::connection, "closed");
		}

		http::async_write(
			socket_,
			response_,
			[self](boost::beast::error_code ec, std::size_t) {
				if (self->request_.version() == 10)
				{
					self->socket_.shutdown(tcp::socket::shutdown_send, ec);
					self->deadline_.cancel();
				}
				else
				{
					self->remaining_ -= 1;
					self->deadline_.expires_after(std::chrono::seconds(60));
					self->read_request();
				}
			});
	}

	// Check whether we have spent enough time on this connection.
	void check_deadline()
	{
		auto self = shared_from_this();

		deadline_.async_wait(
			[self](boost::beast::error_code ec) {
				if (ec == boost::asio::error::operation_aborted)
				{
					self->check_deadline();
				}
				else if (!ec)
				{
					// Close socket to cancel any outstanding operation.
					self->socket_.close(ec);
				}
			});
	}
};

// Recurse forever accepting new connections.
class http_server
{
public:
	http_server(tcp::acceptor& acceptor, tcp::socket& socket) : acceptor_(acceptor),
		socket_(socket)
	{
		load_server_certificate(context_);
		accept();
	}

private:
	tcp::acceptor& acceptor_;
	tcp::socket& socket_;
	boost::asio::ssl::context context_{ssl::context::tlsv12};
	
	void accept()
	{
		acceptor_.async_accept(socket_,
			[&](boost::beast::error_code ec) {
				if (!ec)
					std::make_shared<http_connection>(std::move(socket_), context_)->start();

				accept();
			});
	}
};

int main()
{
	try
	{
		auto const address = boost::asio::ip::make_address("0.0.0.0");
		unsigned short port = static_cast<unsigned short>(80);
		
		boost::asio::io_context ioc{ 1 };

		tcp::acceptor acceptor{ ioc, {address, port} };
		tcp::socket socket{ ioc };
		http_server(acceptor, socket);

		ioc.run();
	}
	catch (std::exception const& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}

	return 0;
}
