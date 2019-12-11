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

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

using tcp = boost::asio::ip::tcp;     // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl;     // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;  // from <boost/beast/http.hpp>

class http_client {
  ssl::context& ctx_;
  boost::beast::tcp_stream stream_;

public:
  http_client(boost::asio::io_context& ioc,
              ssl::context& ctx,
              tcp::endpoint endpoint)
      : stream_{ioc}, ctx_{ctx}
  {
    stream_.connect(endpoint);
  }

  http::response<http::dynamic_body> get(boost::beast::string_view target)
  {
    return request(http::verb::get, target);
  }

  http::response<http::dynamic_body> request(http::verb method,
                                             boost::beast::string_view target)
  {
    // Set up an HTTP GET request message
    http::request<http::string_body> req{method, target, 11};
    req.set(http::field::host, stream_.remote_endpoint().address().to_string());
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    http::write(stream_, req);  // Send the HTTP request to the remote host

    boost::beast::flat_buffer buffer;        // This buffer is used for reading and must be persisted
    http::response<http::dynamic_body> res;  // Declare a container to hold the response

    http::read(stream_, buffer, res);  // Receive the HTTP response
  }
};