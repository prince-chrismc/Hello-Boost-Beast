//
// Copyright (c) 2016-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

//------------------------------------------------------------------------------
//
// Example: HTTP SSL server, asynchronous
//
//------------------------------------------------------------------------------

#include "server_certificate.hpp"

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast.hpp>
#include <boost/bind.hpp>
#include <memory>
#include <string>

using tcp = boost::asio::ip::tcp;     // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl;     // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;  // from <boost/beast/http.hpp>

// Return a reasonable mime type based on the extension of a file.
boost::beast::string_view mime_type(boost::beast::string_view path)
{
  using boost::beast::iequals;
  auto const ext = [&path] {
    auto const pos = path.rfind(".");
    if (pos == boost::beast::string_view::npos)
      return boost::beast::string_view{};
    return path.substr(pos);
  }();
  if (iequals(ext, ".htm")) return "text/html";
  if (iequals(ext, ".html")) return "text/html";
  if (iequals(ext, ".php")) return "text/html";
  if (iequals(ext, ".css")) return "text/css";
  if (iequals(ext, ".txt")) return "text/plain";
  if (iequals(ext, ".js")) return "application/javascript";
  if (iequals(ext, ".json")) return "application/json";
  if (iequals(ext, ".xml")) return "application/xml";
  if (iequals(ext, ".swf")) return "application/x-shockwave-flash";
  if (iequals(ext, ".flv")) return "video/x-flv";
  if (iequals(ext, ".png")) return "image/png";
  if (iequals(ext, ".jpe")) return "image/jpeg";
  if (iequals(ext, ".jpeg")) return "image/jpeg";
  if (iequals(ext, ".jpg")) return "image/jpeg";
  if (iequals(ext, ".gif")) return "image/gif";
  if (iequals(ext, ".bmp")) return "image/bmp";
  if (iequals(ext, ".ico")) return "image/vnd.microsoft.icon";
  if (iequals(ext, ".tiff")) return "image/tiff";
  if (iequals(ext, ".tif")) return "image/tiff";
  if (iequals(ext, ".svg")) return "image/svg+xml";
  if (iequals(ext, ".svgz")) return "image/svg+xml";
  return "application/text";
}

// Append an HTTP rel-path to a local filesystem path. The returned path is normalized for the platform.
std::string path_cat(boost::beast::string_view base, boost::beast::string_view path)
{
  if (base.empty()) return path.to_string();
  std::string result = base.to_string();
#if BOOST_MSVC
  char constexpr path_separator = '\\';
  if (result.back() == path_separator) result.resize(result.size() - 1);
  result.append(path.data(), path.size());
  for (auto& c : result)
    if (c == '/') c = path_separator;
#else
  char constexpr path_separator = '/';
  if (result.back() == path_separator) result.resize(result.size() - 1);
  result.append(path.data(), path.size());
#endif
  return result;
}

template <class Body>
void set_connection_status_headers(http::response<Body>& out_msg, unsigned version, size_t remaining)
{
  if (version == 11) {
    if (remaining > 0) {
      out_msg.set(http::field::keep_alive, "timeout=60, max=" + std::to_string(remaining));
    }
    else {
      out_msg.keep_alive(false);
    }
  }
  else {
    out_msg.keep_alive(false);
    out_msg.set(http::field::connection, "closed");
  }
}

boost::beast::string_param get_date_value()
{
  char buf[256];
  const time_t now = time(0);
  const tm tm = *gmtime(&now);
  const auto len = strftime(buf, sizeof buf, "%a, %d %b %Y %H:%M:%S %Z", &tm);

  return {buf, len};
}

// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template <class Body, class Allocator, class Send>
void handle_request(boost::beast::string_view doc_root,
                    http::request<Body, http::basic_fields<Allocator>>&& req,
                    const size_t remaining,
                    Send&& send)
{
  // Returns a bad request response
  auto const bad_request = [&req, remaining](boost::beast::string_view why) {
    http::response<http::string_body> res{http::status::bad_request, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::date, get_date_value());
    res.set(http::field::content_type, "text/html");
    set_connection_status_headers<http::string_body>(res, req.version(), remaining);
    res.body() = why.to_string();
    res.prepare_payload();
    return res;
  };

  // Returns a not found response
  auto const not_found = [&req, remaining](boost::beast::string_view target) {
    http::response<http::string_body> res{http::status::not_found, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::date, get_date_value());
    res.set(http::field::content_type, "text/html");
    set_connection_status_headers<http::string_body>(res, req.version(), remaining);
    res.body() = "The resource '" + target.to_string() + "' was not found.";
    res.prepare_payload();
    return res;
  };

  // Returns a server error response
  auto const server_error = [&req, remaining](boost::beast::string_view what) {
    http::response<http::string_body> res{http::status::internal_server_error, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::date, get_date_value());
    res.set(http::field::content_type, "text/html");
    set_connection_status_headers<http::string_body>(res, req.version(), remaining);
    res.body() = "An error occurred: '" + what.to_string() + "'";
    res.prepare_payload();
    return res;
  };

  // Make sure we can handle the method
  if (req.method() != http::verb::get && req.method() != http::verb::head)
    return send(bad_request("Unknown HTTP-method"));

  // Request path must be absolute and not contain "..".
  if (req.target().empty() || req.target()[0] != '/' || req.target().find("..") != boost::beast::string_view::npos)
    return send(bad_request("Illegal request-target"));

  // Build the path to the requested file
  std::string path = path_cat(doc_root, req.target());
  if (req.target().back() == '/') path.append("index.html");

  // Attempt to open the file
  boost::beast::error_code ec;
  http::file_body::value_type body;
  body.open(path.c_str(), boost::beast::file_mode::scan, ec);

  // Handle the case where the file doesn't exist
  if (ec == boost::system::errc::no_such_file_or_directory)
    return send(not_found(req.target()));

  // Handle an unknown error
  if (ec) return send(server_error(ec.message()));

  // Cache the size since we need it after the move
  auto const size = body.size();

  // Respond to HEAD request
  if (req.method() == http::verb::head) {
    http::response<http::empty_body> res{http::status::ok, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::date, get_date_value());
    res.set(http::field::content_type, mime_type(path));
    res.content_length(size);
    set_connection_status_headers<http::empty_body>(res, req.version(), remaining);
    return send(std::move(res));
  }

  // Respond to GET request
  http::response<http::file_body> res{
      std::piecewise_construct, std::make_tuple(std::move(body)),
      std::make_tuple(http::status::ok, req.version())};
  res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
  res.set(http::field::date, get_date_value());
  res.set(http::field::content_type, mime_type(path));
  res.content_length(size);
  set_connection_status_headers<http::file_body>(res, req.version(), remaining);
  return send(std::move(res));
}

//------------------------------------------------------------------------------

// Handles an HTTP server connection
class https_connection : public std::enable_shared_from_this<https_connection> {
  // This is the C++11 equivalent of a generic lambda.
  // The function object is used to send an HTTP message.
  struct send_lambda {
    https_connection& self_;

    explicit send_lambda(https_connection& self) : self_(self) {}

    template <bool isRequest, class Body, class Fields>
    void operator()(http::message<isRequest, Body, Fields>&& msg) const
    {
      // The lifetime of the message has to extend
      // for the duration of the async operation so
      // we use a shared_ptr to manage it.
      auto sp = std::make_shared<http::message<isRequest, Body, Fields>>(
          std::move(msg));

      // Store a type-erased version of the shared
      // pointer in the class to keep it alive.
      self_.res_ = sp;

      // Write the response
      http::async_write(
          self_.stream_, *sp,
          boost::asio::bind_executor(
              self_.strand_,
              boost::bind(&https_connection::on_write, self_.shared_from_this(),
                          boost::asio::placeholders::error,
                          boost::asio::placeholders::bytes_transferred,
                          sp->need_eof())));
    }
  };

  tcp::socket socket_;
  ssl::stream<tcp::socket&> stream_;
  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
  boost::beast::flat_buffer buffer_;
  std::shared_ptr<std::string const> doc_root_;
  http::request<http::string_body> req_;
  std::shared_ptr<void> res_;
  send_lambda lambda_;

  boost::asio::basic_waitable_timer<std::chrono::steady_clock> deadline_{
      socket_.get_executor().context(), std::chrono::seconds(60)};  // The timer for putting a deadline on connection processing.
  size_t remaining_{50};

public:
  // Take ownership of the socket
  explicit https_connection(tcp::socket socket, ssl::context& ctx,
                            std::shared_ptr<std::string const> const& doc_root)
      : socket_(std::move(socket)),
        stream_(socket_, ctx),
        strand_(socket_.get_executor()),
        doc_root_(doc_root),
        lambda_(*this)
  {
  }

  // Start the asynchronous operation
  void run()
  {
    auto self = shared_from_this();
    // Perform the SSL handshake
    stream_.async_handshake(
        ssl::stream_base::server,
        boost::asio::bind_executor(
            strand_,
            [self](boost::system::error_code ec) {
              if (!ec)
                self->on_handshake(ec);
            }));
  }

  void on_handshake(boost::system::error_code ec)
  {
    do_read();
    check_deadline();
  }

  void do_read()
  {
    // Make the request empty before reading,
    // otherwise the operation behavior is undefined.
    req_ = {};

    // Read a request
    http::async_read(
        stream_, buffer_, req_,
        boost::asio::bind_executor(
            strand_, boost::bind(&https_connection::on_read,
                                 shared_from_this(),
                                 boost::asio::placeholders::error,
                                 boost::asio::placeholders::bytes_transferred)));
  }

  void on_read(boost::system::error_code ec, std::size_t bytes_transferred)
  {
    boost::ignore_unused(bytes_transferred);

    // This means they closed the connection
    if (ec == http::error::end_of_stream || ec == boost::asio::ssl::error::stream_truncated)
      return do_close();

    boost::asio::detail::throw_error(ec, "read");

    // Send the response
    handle_request(*doc_root_, std::move(req_), --remaining_, lambda_);
  }

  void on_write(boost::system::error_code ec, std::size_t bytes_transferred, bool close)
  {
    boost::ignore_unused(bytes_transferred);

    boost::asio::detail::throw_error(ec, "write");

    if (close || req_.version() == 10 || remaining_ <= 0) {
      // This means we should close the connection, usually because
      // the response indicated the "Connection: close" semantic.
      return do_close();
    }

    // We're done with the response so delete it
    res_ = nullptr;

    deadline_.expires_after(std::chrono::seconds(60));

    // Read another request
    do_read();
  }

  // Check whether we have spent enough time on this connection.
  void check_deadline()
  {
    auto self = shared_from_this();

    deadline_.async_wait(
        [self](boost::beast::error_code ec) {
          if (ec == boost::asio::error::operation_aborted) {
            self->check_deadline();
          }
          else if (!ec) {
            // Close socket to cancel any outstanding operation.
            self->do_close();
          }
        });
  }

  void do_close()
  {
    // Perform the SSL shutdown
    auto self = shared_from_this();
    stream_.async_shutdown(boost::asio::bind_executor(
        strand_, [self](boost::system::error_code ec) { self->on_shutdown(ec); }));
  }

  void on_shutdown(boost::system::error_code ec)
  {
    if (ec != boost::asio::error::eof &&                  // if remote has not already close underlying socket. https://stackoverflow.com/a/25703699/8480874
        ec != boost::asio::ssl::error::stream_truncated)  // client closed socket without doing ssl shutdown https://github.com/boostorg/beast/issues/38
      boost::asio::detail::throw_error(ec, "shutdown");

    deadline_.cancel();
    stream_.lowest_layer().close();
    // At this point the connection is closed gracefully
  }
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the sessions
class https_server : public std::enable_shared_from_this<https_server> {
  ssl::context& ctx_;
  tcp::acceptor acceptor_;
  tcp::socket socket_;
  std::shared_ptr<std::string const> doc_root_;

public:
  https_server(boost::asio::io_context& ioc,
               ssl::context& ctx,
               tcp::endpoint endpoint,
               std::shared_ptr<std::string const> const& doc_root)
      : ctx_(ctx), acceptor_(ioc), socket_(ioc), doc_root_(doc_root)
  {
    using socket = boost::asio::socket_base;
    acceptor_.open(endpoint.protocol());                // Open the acceptor
    acceptor_.set_option(socket::reuse_address(true));  // Allow address reuse
    acceptor_.bind(endpoint);                           // Bind to the server address
    acceptor_.listen(socket::max_listen_connections);   // Start listening for connections
  }

  // Start accepting incoming connections
  void run()
  {
    if (!acceptor_.is_open()) return;
    do_accept();
  }

  void do_accept()
  {
    auto self = shared_from_this();
    acceptor_.async_accept(socket_,
                           [self](boost::system::error_code ec) {
                             boost::asio::detail::throw_error(ec, "accept");
                             self->on_accept();
                           });
  }

  void on_accept()
  {
    // Create the https_connection and run it
    std::make_shared<https_connection>(std::move(socket_), ctx_, doc_root_)->run();
    do_accept();  // Accept another connection
  }
};

//------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
  // Check command line arguments.
  if (argc != 4) {
    std::cerr << "Usage: http-server-async-ssl <address> <port> <doc_root>\n"
              << "Example:\n    " << argv[0] << " 0.0.0.0 8443 . \n";
    return EXIT_FAILURE;
  }

  auto const address = boost::asio::ip::make_address(argv[1]);
  auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
  auto const doc_root = std::make_shared<std::string>(argv[3]);

  boost::asio::io_context ioc{1};       // The io_context is required for all I/O
  ssl::context ctx{ssl::context::tls};  // The SSL context is required, and holds certificates
  load_server_certificate(ctx);         // This holds the self-signed certificate used by the server

  // Create and launch a listening port
  std::make_shared<https_server>(ioc, ctx, tcp::endpoint{address, port}, doc_root)->run();

  ioc.run();

  return EXIT_SUCCESS;
}
