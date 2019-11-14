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

#include <boost/array.hpp>
#include <boost/beast.hpp>
#include <boost/optional.hpp>
#include <boost/regex.hpp>
#include <functional>
#include <map>

namespace detail {
template <int... Is>
struct seq {
};

template <int N, int... Is>
struct gen_seq : gen_seq<N - 1, N - 1, Is...> {
};

template <int... Is>
struct gen_seq<0, Is...> : seq<Is...> {
};

template <typename T>
struct count_arg;

template <typename R, typename... Args>
struct count_arg<std::function<R(Args...)>> {
  static const size_t value = sizeof...(Args);
};

template <typename F, typename T, int N>
class CallbackContainer {
public:
  template <typename... Ts>
  CallbackContainer(F func, Ts&&... vs) : func{func},
                                          data{{std::forward<Ts>(vs)...}}
  {
    static_assert(sizeof...(Ts) == N, "Not enough args supplied!");
  }

  void invoke()
  {
    invoke(std::forward<F>(func), detail::gen_seq<N>());
  }

private:
  template <int... Is>
  void invoke(detail::seq<Is...>)
  {
    (std::forward<F>(func))(data[Is]...);
  }

  F func;
  boost::array<T, N> data;
};
}  // namespace detail

namespace http = boost::beast::http;

template <class Request = http::request<http::empty_body>,
          class Response = http::response<http::string_body>>
class restful_server {
  using process = std::function<Response(Request&&)>;

  boost::optional<process> generic_handler_;
  std::map<http::verb, process> handlers_;
  std::map<http::verb, std::map<boost::string_view, process>> path_handlers_;

public:
  void support(const process& handler) { generic_handler_ = handler; }
  void support(const http::verb& method, const process& handler)
  {
    handlers_[method] = handler;
  }
  void support(const http::verb& method, const boost::string_view& uri, const process& handler)
  {
    path_handlers_[method][uri] = handler;
  }

  Response operator()(Request&& req)
  {
    const auto uri = req.target();

    boost::smatch what;
    boost::regex pattern = uri;
    if (boost::regex_match(uri, what, pattern)) {
    }
    if (handlers_.count(req.method())) {
      return handlers_[req.method()];
    }
    else if (generic_handler_.has_value()) {
      return *generic_handler_(req);
    }
  }
};
