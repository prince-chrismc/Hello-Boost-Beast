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
  const std::string cert_chain = R"###(-----BEGIN CERTIFICATE-----
MIICRjCCAeugAwIBAgIUd9kvSZtlpRjBbQffBFHSfWRmif8wCgYIKoZIzj0EAwIw
bzELMAkGA1UEBhMCQ0ExDzANBgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJpbmNl
LWNocmlzbWMxGjAYBgNVBAsMEUhlbGxvLUJvb3N0LUJlYXN0MRowGAYDVQQDDBFj
YS50ZXN0c2VydmVyLmxhbjAgFw0xOTEwMDQwMDM1MDhaGA8yMDY5MDkyMTAwMzUw
OFowbzELMAkGA1UEBhMCQ0ExDzANBgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJp
bmNlLWNocmlzbWMxGjAYBgNVBAsMEUhlbGxvLUJvb3N0LUJlYXN0MRowGAYDVQQD
DBFjYS50ZXN0c2VydmVyLmxhbjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNGb
XbjD46tg8+TeHiFW13/cJvL4ZEKmt7TcG7D8o0CI5SFtChhznD3FOLruCjHPoqch
StsV3msCzXvkmCRNBLqjYzBhMB0GA1UdDgQWBBTpzIBfyyGXtuHTCl+V7XWfPTb7
RjAfBgNVHSMEGDAWgBTpzIBfyyGXtuHTCl+V7XWfPTb7RjAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAgNJADBGAiEAm3QrNMHXHM9S
ViJb9KnZIYLWQY+mpQw26sBmyTcMUxwCIQCtu7+PnNdd/oA0qoWG+ckRaNQk10wx
t/HPKw6yf3nARQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDDjCCArSgAwIBAgICEAEwCgYIKoZIzj0EAwIwcDELMAkGA1UEBhMCQ0ExDzAN
BgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJpbmNlLWNocmlzbWMxGjAYBgNVBAsM
EUhlbGxvLUJvb3N0LUJlYXN0MRswGQYDVQQDDBJpY2EudGVzdHNlcnZlci5sYW4w
IBcNMTkxMDA0MDAzNTA5WhgPMjA2OTA5MjEwMDM1MDlaMHIxCzAJBgNVBAYTAkNB
MQ8wDQYDVQQIDAZRdWViZWMxFzAVBgNVBAoMDnByaW5jZS1jaHJpc21jMRowGAYD
VQQLDBFIZWxsby1Cb29zdC1CZWFzdDEdMBsGA1UEAwwUaHR0cHMudGVzdHNlcnZl
ci5sYW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQM5CueXxWL7GB6WGQSF4MD
6I34FaGfj2jdKNNDNMtWlX9VhBBFkAPqEXO05x9gMSsSZpdiyu4WAPQIU+5FtFFs
o4IBODCCATQwCQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMCBkAwMwYJYIZIAYb4
QgENBCYWJE9wZW5TU0wgR2VuZXJhdGVkIFNlcnZlciBDZXJ0aWZpY2F0ZTAdBgNV
HQ4EFgQUvZDu1dEn/84QKqFTkg55fGqFzB8wgZoGA1UdIwSBkjCBj4AUCXw4jwqC
lhrgmvPgVcqh/gz2KNmhc6RxMG8xCzAJBgNVBAYTAkNBMQ8wDQYDVQQIDAZRdWVi
ZWMxFzAVBgNVBAoMDnByaW5jZS1jaHJpc21jMRowGAYDVQQLDBFIZWxsby1Cb29z
dC1CZWFzdDEaMBgGA1UEAwwRY2EudGVzdHNlcnZlci5sYW6CAhAAMA4GA1UdDwEB
/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgNIADBFAiBv
XQTYXqH4I8nh0fC7m76LWJR0j0onSj6NbVhTXM+8CAIhAONlsQ9ZSzFgR1YFb26q
lGsmD6axHKeR6vFldPnfQRkG
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICRjCCAeugAwIBAgIUd9kvSZtlpRjBbQffBFHSfWRmif8wCgYIKoZIzj0EAwIw
bzELMAkGA1UEBhMCQ0ExDzANBgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJpbmNl
LWNocmlzbWMxGjAYBgNVBAsMEUhlbGxvLUJvb3N0LUJlYXN0MRowGAYDVQQDDBFj
YS50ZXN0c2VydmVyLmxhbjAgFw0xOTEwMDQwMDM1MDhaGA8yMDY5MDkyMTAwMzUw
OFowbzELMAkGA1UEBhMCQ0ExDzANBgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJp
bmNlLWNocmlzbWMxGjAYBgNVBAsMEUhlbGxvLUJvb3N0LUJlYXN0MRowGAYDVQQD
DBFjYS50ZXN0c2VydmVyLmxhbjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNGb
XbjD46tg8+TeHiFW13/cJvL4ZEKmt7TcG7D8o0CI5SFtChhznD3FOLruCjHPoqch
StsV3msCzXvkmCRNBLqjYzBhMB0GA1UdDgQWBBTpzIBfyyGXtuHTCl+V7XWfPTb7
RjAfBgNVHSMEGDAWgBTpzIBfyyGXtuHTCl+V7XWfPTb7RjAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAgNJADBGAiEAm3QrNMHXHM9S
ViJb9KnZIYLWQY+mpQw26sBmyTcMUxwCIQCtu7+PnNdd/oA0qoWG+ckRaNQk10wx
t/HPKw6yf3nARQ==
-----END CERTIFICATE-----
)###";

  const std::string cert = R"###(-----BEGIN CERTIFICATE-----
MIICRjCCAeugAwIBAgIUd9kvSZtlpRjBbQffBFHSfWRmif8wCgYIKoZIzj0EAwIw
bzELMAkGA1UEBhMCQ0ExDzANBgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJpbmNl
LWNocmlzbWMxGjAYBgNVBAsMEUhlbGxvLUJvb3N0LUJlYXN0MRowGAYDVQQDDBFj
YS50ZXN0c2VydmVyLmxhbjAgFw0xOTEwMDQwMDM1MDhaGA8yMDY5MDkyMTAwMzUw
OFowbzELMAkGA1UEBhMCQ0ExDzANBgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJp
bmNlLWNocmlzbWMxGjAYBgNVBAsMEUhlbGxvLUJvb3N0LUJlYXN0MRowGAYDVQQD
DBFjYS50ZXN0c2VydmVyLmxhbjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNGb
XbjD46tg8+TeHiFW13/cJvL4ZEKmt7TcG7D8o0CI5SFtChhznD3FOLruCjHPoqch
StsV3msCzXvkmCRNBLqjYzBhMB0GA1UdDgQWBBTpzIBfyyGXtuHTCl+V7XWfPTb7
RjAfBgNVHSMEGDAWgBTpzIBfyyGXtuHTCl+V7XWfPTb7RjAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAgNJADBGAiEAm3QrNMHXHM9S
ViJb9KnZIYLWQY+mpQw26sBmyTcMUxwCIQCtu7+PnNdd/oA0qoWG+ckRaNQk10wx
t/HPKw6yf3nARQ==
-----END CERTIFICATE-----
)###";

  const std::string key = R"###(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJEwUtM9Wi1F0nrTCMZwXyp7H4/c4CqYILQckpgVw9UMoAoGCCqGSM49
AwEHoUQDQgAEDOQrnl8Vi+xgelhkEheDA+iN+BWhn49o3SjTQzTLVpV/VYQQRZAD
6hFztOcfYDErEmaXYsruFgD0CFPuRbRRbA==
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
      boost::asio::buffer(cert_chain.data(), cert_chain.size()));

  ctx.use_certificate(
      boost::asio::buffer(cert.data(), cert.size()),
      boost::asio::ssl::context::file_format::pem);

  use_tmp_ecdh(ctx, boost::asio::buffer(cert.data(), cert.size()));

  ctx.use_private_key(
      boost::asio::buffer(key.data(), key.size()),
      boost::asio::ssl::context::file_format::pem);

  ctx.use_tmp_dh(boost::asio::buffer(dh.data(), dh.size()));
}

#endif
