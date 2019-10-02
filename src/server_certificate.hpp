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

#ifndef BOOST_BEAST_EXAMPLE_COMMON_SERVER_CERTIFICATE_HPP
#define BOOST_BEAST_EXAMPLE_COMMON_SERVER_CERTIFICATE_HPP

#include "use_tmp_ecdh.hpp"

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
