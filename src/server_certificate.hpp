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
MIIDDTCCArSgAwIBAgICEAEwCgYIKoZIzj0EAwIwcDELMAkGA1UEBhMCQ0ExDzAN
BgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJpbmNlLWNocmlzbWMxGjAYBgNVBAsM
EUhlbGxvLUJvb3N0LUJlYXN0MRswGQYDVQQDDBJpY2EudGVzdHNlcnZlci5sYW4w
IBcNMTkxMDEyMDEzMDA3WhgPMjA2OTA5MjkwMTMwMDdaMHIxCzAJBgNVBAYTAkNB
MQ8wDQYDVQQIDAZRdWViZWMxFzAVBgNVBAoMDnByaW5jZS1jaHJpc21jMRowGAYD
VQQLDBFIZWxsby1Cb29zdC1CZWFzdDEdMBsGA1UEAwwUaHR0cHMudGVzdHNlcnZl
ci5sYW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARkw5+hXle55kdJYresYo+I
WTZGunxP/AfFJdBpTX7M8DCEYSmx9t/5ad/kr3XMtKTxJ3ZllZiaq7zS9UHWeEEW
o4IBODCCATQwCQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMCBkAwMwYJYIZIAYb4
QgENBCYWJE9wZW5TU0wgR2VuZXJhdGVkIFNlcnZlciBDZXJ0aWZpY2F0ZTAdBgNV
HQ4EFgQUkXyZ0Ls88GuLgMEJVwe3REPfww8wgZoGA1UdIwSBkjCBj4AUw8R57MEn
OoLJSyBIdI9EQRjlYJyhc6RxMG8xCzAJBgNVBAYTAkNBMQ8wDQYDVQQIDAZRdWVi
ZWMxFzAVBgNVBAoMDnByaW5jZS1jaHJpc21jMRowGAYDVQQLDBFIZWxsby1Cb29z
dC1CZWFzdDEaMBgGA1UEAwwRY2EudGVzdHNlcnZlci5sYW6CAhAAMA4GA1UdDwEB
/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgNHADBEAiAW
LnGLDlgeHFd2E5kpvPWH7TZH6r/K/V56eg4q+k6hfQIgZPo5QwhuNQ+gMhZiTejq
wVO2GNW75fMRry3+zw/ythM=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICNzCCAd2gAwIBAgICEAAwCgYIKoZIzj0EAwIwbzELMAkGA1UEBhMCQ0ExDzAN
BgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJpbmNlLWNocmlzbWMxGjAYBgNVBAsM
EUhlbGxvLUJvb3N0LUJlYXN0MRowGAYDVQQDDBFjYS50ZXN0c2VydmVyLmxhbjAg
Fw0xOTEwMTIwMTMwMDZaGA8yMDY5MDkyOTAxMzAwNlowcDELMAkGA1UEBhMCQ0Ex
DzANBgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJpbmNlLWNocmlzbWMxGjAYBgNV
BAsMEUhlbGxvLUJvb3N0LUJlYXN0MRswGQYDVQQDDBJpY2EudGVzdHNlcnZlci5s
YW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARkjtN8KUo32ZDt+dOAeRb+8a0n
jD+KPlKeXoSpP1DFJUsRaI2w0rPkEP0P73QQY1xypb6cSjH0Ht8bYigZpyRPo2Yw
ZDAdBgNVHQ4EFgQUw8R57MEnOoLJSyBIdI9EQRjlYJwwHwYDVR0jBBgwFoAU8GsQ
uTJAJ9pHu0XrtXozkV1WKPMwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8E
BAMCAYYwCgYIKoZIzj0EAwIDSAAwRQIhAJwzqgSZ8ftl4UfPuuox6rbvxO9hb5Gd
8aHzFdc6Jv9wAiAnZKWsFvwiA1r5DxMzzvWY88ayntYqRATJbetoemYAdg==
-----END CERTIFICATE-----
)###";

  const std::string key = R"###(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKrPfubIoE14TGp30mrbbyT10vcpKFzUyARmdFJZVn/hoAoGCCqGSM49
AwEHoUQDQgAEZMOfoV5XueZHSWK3rGKPiFk2Rrp8T/wHxSXQaU1+zPAwhGEpsfbf
+Wnf5K91zLSk8Sd2ZZWYmqu80vVB1nhBFg==
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
