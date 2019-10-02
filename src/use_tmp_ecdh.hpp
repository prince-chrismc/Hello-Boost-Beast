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

#ifndef HELLO_BOOST_BEAST_USE_TMP_ECDH_HPP
#define HELLO_BOOST_BEAST_USE_TMP_ECDH_HPP

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ssl/context.hpp>

BIO* make_buffer_bio(const boost::asio::const_buffer& b)
{
  return ::BIO_new_mem_buf(
      const_cast<void*>(b.data()),
      static_cast<int>(b.size()));
}

struct bio_cleanup {
  BIO* p;
  ~bio_cleanup()
  {
    if (p) ::BIO_free(p);
  }
};

struct x509_cleanup {
  X509* p;
  ~x509_cleanup()
  {
    if (p) ::X509_free(p);
  }
};

struct evp_pkey_cleanup {
  EVP_PKEY* p;
  ~evp_pkey_cleanup()
  {
    if (p) ::EVP_PKEY_free(p);
  }
};

struct ec_key_cleanup {
  EC_KEY* p;
  ~ec_key_cleanup()
  {
    if (p) ::EC_KEY_free(p);
  }
};

BOOST_ASIO_SYNC_OP_VOID do_use_tmp_ecdh(
    boost::asio::ssl::context& ctx,
    BIO* bio,
    boost::system::error_code& ec)
{
  ::ERR_clear_error();

  int nid = NID_undef;

  x509_cleanup x509 = {::PEM_read_bio_X509(bio, NULL, 0, NULL)};
  if (x509.p) {
    evp_pkey_cleanup pkey = {::X509_get_pubkey(x509.p)};
    if (pkey.p) {
      ec_key_cleanup tmp = {::EVP_PKEY_get1_EC_KEY(pkey.p)};
      if (tmp.p) {
        const EC_GROUP* group = EC_KEY_get0_group(tmp.p);
        nid = EC_GROUP_get_curve_name(group);
      }
    }
  }

  ec_key_cleanup ec_key = {::EC_KEY_new_by_curve_name(nid)};
  if (ec_key.p) {
    if (::SSL_CTX_set_tmp_ecdh(ctx.native_handle(), ec_key.p) == 1) {
      ec = boost::system::error_code();
      BOOST_ASIO_SYNC_OP_VOID_RETURN(ec);
    }
  }

  ec = boost::system::error_code(
      static_cast<int>(::ERR_get_error()),
      boost::asio::error::get_ssl_category());
  BOOST_ASIO_SYNC_OP_VOID_RETURN(ec);
}

BOOST_ASIO_SYNC_OP_VOID use_tmp_ecdh(boost::asio::ssl::context& ctx,
                                     const boost::asio::const_buffer& certificate,
                                     boost::system::error_code& ec)
{
  ::ERR_clear_error();

  bio_cleanup bio = {make_buffer_bio(certificate)};
  if (bio.p) {
    return do_use_tmp_ecdh(ctx, bio.p, ec);
  }

  ec = boost::system::error_code(
      static_cast<int>(::ERR_get_error()),
      boost::asio::error::get_ssl_category());
  BOOST_ASIO_SYNC_OP_VOID_RETURN(ec);
}

void use_tmp_ecdh(boost::asio::ssl::context& ctx,
                  const boost::asio::const_buffer& certificate)
{
  boost::system::error_code ec;
  use_tmp_ecdh(ctx, certificate, ec);
  boost::asio::detail::throw_error(ec, "use_tmp_ecdh");
}

#endif  // HELLO_BOOST_BEAST_USE_TMP_ECDH_HPP
