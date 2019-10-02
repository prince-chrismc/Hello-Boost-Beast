//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef BOOST_BEAST_EXAMPLE_COMMON_SERVER_CERTIFICATE_HPP
#define BOOST_BEAST_EXAMPLE_COMMON_SERVER_CERTIFICATE_HPP

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ssl/context.hpp>
#include <cstddef>
#include <memory>

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

BOOST_ASIO_SYNC_OP_VOID use_tmp_ecdh_file(boost::asio::ssl::context& ctx,
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
  use_tmp_ecdh_file(ctx, certificate, ec);
  boost::asio::detail::throw_error(ec, "use_tmp_ecdh");
}

// Load a signed certificate into the ssl context, and configure
// the context for use with a server.
inline void load_server_certificate(boost::asio::ssl::context& ctx)
{
  const std::string cert = R"###(-----BEGIN CERTIFICATE-----
MIICtzCCAl2gAwIBAgICEAEwCgYIKoZIzj0EAwIwVDELMAkGA1UEBhMCQ0ExDzAN
BgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJpbmNlLWNocmlzbWMxGzAZBgNVBAMM
EmljYS50ZXN0c2VydmVyLmxhbjAgFw0xOTA5MjgwMDI1MjBaGA8yMDY5MDkxNTAw
MjUyMFowVjELMAkGA1UEBhMCQ0ExDzANBgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwO
cHJpbmNlLWNocmlzbWMxHTAbBgNVBAMMFGh0dHBzLnRlc3RzZXJ2ZXIubGFuMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+U9mvQjkrsURvIPCdaG98U61su9mhdMS
xwqbiz+Qob7XNwWRYDKcIpE5eMRiBhqNNR46ts1lkkPxN4jViUaz5aOCARkwggEV
MAkGA1UdEwQCMAAwEQYJYIZIAYb4QgEBBAQDAgZAMDMGCWCGSAGG+EIBDQQmFiRP
cGVuU1NMIEdlbmVyYXRlZCBTZXJ2ZXIgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFL8w
shrriGvBrAqRxdJw75lV8ZBWMHwGA1UdIwR1MHOAFCB4UiqL5NDrUaEweOdq5JIp
IE6XoVekVTBTMQswCQYDVQQGEwJDQTEPMA0GA1UECAwGUXVlYmVjMRcwFQYDVQQK
DA5wcmluY2UtY2hyaXNtYzEaMBgGA1UEAwwRY2EudGVzdHNlcnZlci5sYW6CAhAA
MA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAKBggqhkjOPQQD
AgNIADBFAiEArpZoyIen4R4iOxpIvwA5402nY4Krk0pYxPoyAwQBG7cCIBYiOUWe
cL9uQjCUnJQS/1+UV+inqZz7367yWSCKMdVo
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICDDCCAbOgAwIBAgIUJNye5eWw6uLiYGKx0YPmuAOxwZQwCgYIKoZIzj0EAwIw
UzELMAkGA1UEBhMCQ0ExDzANBgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJpbmNl
LWNocmlzbWMxGjAYBgNVBAMMEWNhLnRlc3RzZXJ2ZXIubGFuMCAXDTE5MDkyNjAw
MzIyN1oYDzIwNjkwOTEzMDAzMjI3WjBTMQswCQYDVQQGEwJDQTEPMA0GA1UECAwG
UXVlYmVjMRcwFQYDVQQKDA5wcmluY2UtY2hyaXNtYzEaMBgGA1UEAwwRY2EudGVz
dHNlcnZlci5sYW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARwAmznU2yoTKW3
XIbfoPHZAoervdCmOo9rP+uuQFK4aTfGL9YbdxBEmT7CZLFeCAhQfzh9jdVsz/qL
WMF6n3Rzo2MwYTAdBgNVHQ4EFgQUszKCfzlSl54nDpRdS1DGnOcAIRAwHwYDVR0j
BBgwFoAUszKCfzlSl54nDpRdS1DGnOcAIRAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDRwAwRAIgP2nFxq3xx6j21FJS/fgCjKUs
vD/s8xa95p+ZrN/Zu6ECID1hk+lh4sHtTr+LQunwc43a0l4EF05XvHK8/DwsP660
-----END CERTIFICATE-----

)###";

  const std::string key = R"###(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMWuPJYabrHT++q496TrYik+kUx60z2RNZbWQdaEQLG5oAoGCCqGSM49
AwEHoUQDQgAE+U9mvQjkrsURvIPCdaG98U61su9mhdMSxwqbiz+Qob7XNwWRYDKc
IpE5eMRiBhqNNR46ts1lkkPxN4jViUaz5Q==
-----END EC PRIVATE KEY-----
)###";

  const std::string dh = R"###(-----BEGIN DH PARAMETERS-----
MIICCAKCAgEA6tw4mWDV5C+6eR90Guc6aeJ4tieKYJ7VWfSk34pyLIZkvweP/QfN
03dfzbYwvXNUxX7P1s8WsZgT/pfHLBjJK0B8+YOEWlttuXr1NT/mEBQkbUVf4PyA
RL9RXFx7O9eB7laxx+hh4jwU0Ol1nBGgHYHVSU79W4GYcR/LBQwo3hp6nKgvT2jY
axmervsdt8pprbDiJf3nX4pQlsz9oWNCU5m4tYeJ/cATMBHrT6JnGbEeVs1B/raf
YKyHoDWbDrlS8iHPzn+iTrECgtnmOkhnw8rxqrfXbzTXO+pUa6X+m/0rv2t5+mMb
+NNQsBQq1NMnXHpM1w3rl+ZuiLiywgjpkzy3aO6XfGOZnw4e8UG6izsKvTc9/Jlf
3C8NkAXw7VpwCyLQzSDz6h6CAMWjE10GGxV6/OaEU1vCiyaiFZxLgRDEf+VVTioX
/9IBXkXe4+d8flSvZVnoZF195apPk7ASED9J4CLYi8jLSyA+dZrxp7sh3/rJ18Om
f+fhJuOlE492pmzg0guqDHF8cF1hIs8QBpo8dDVrzgnCUQhSdL/8kKK9KYtjWI2B
HCJFzl3gu5BxLXrDON55snc8DX3SA1vUP9Are+amUjy2HEIvl00UwfPrQMVhH/fc
H512gn0CQpuIr2JV0DkQnezzrIjtSUFCDutuo+cFcpAeGTaGgYm+BTsCAQI=
-----END DH PARAMETERS-----
)###";

  ctx.set_options(
      boost::asio::ssl::context::default_workarounds |
      boost::asio::ssl::context::no_sslv2 |
      boost::asio::ssl::context::no_sslv3 |
      boost::asio::ssl::context::no_tlsv1 |
      boost::asio::ssl::context::single_dh_use);

  ctx.use_certificate_chain(
      boost::asio::buffer(cert.data(), cert.size()));

  use_tmp_ecdh(ctx, boost::asio::buffer(cert.data(), cert.size()));

  ctx.use_private_key(
      boost::asio::buffer(key.data(), key.size()),
      boost::asio::ssl::context::file_format::pem);

  ctx.use_tmp_dh(boost::asio::buffer(dh.data(), dh.size()));
}

#endif
