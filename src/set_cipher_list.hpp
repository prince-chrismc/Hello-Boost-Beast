#ifndef BOOST_ASIO_SSL_SET_CIPHER_LIST_HPP
#define BOOST_ASIO_SSL_SET_CIPHER_LIST_HPP

#include <boost/asio/detail/push_options.hpp>
#include <boost/asio/ssl/context.hpp>

const auto ssl_cipher_list = "HIGH:!kRSA";

inline BOOST_ASIO_SYNC_OP_VOID set_cipher_list(
    boost::asio::ssl::context& ctx,
    const std::string& cipher_list,
    boost::system::error_code& ec)
{
  ::ERR_clear_error();

  if (::SSL_CTX_set_cipher_list(ctx.native_handle(), cipher_list.c_str()) != 1) {
    ec = boost::system::error_code(
        static_cast<int>(::ERR_get_error()),
        boost::asio::error::get_ssl_category());
    BOOST_ASIO_SYNC_OP_VOID_RETURN(ec);
  }

  ec = boost::system::error_code();
  BOOST_ASIO_SYNC_OP_VOID_RETURN(ec);
}

inline void set_cipher_list(
    boost::asio::ssl::context& ctx,
    const std::string& cipher_list)
{
  boost::system::error_code ec;
  set_cipher_list(ctx, cipher_list, ec);
  boost::asio::detail::throw_error(ec, "set_cipher_list");
}

#endif  // BOOST_ASIO_SSL_SET_CIPHER_LIST_HPP
