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
MIICRTCCAeugAwIBAgIUTGWDvNbp/mj3jXONgooGp3yivMIwCgYIKoZIzj0EAwIw
bzELMAkGA1UEBhMCQ0ExDzANBgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJpbmNl
LWNocmlzbWMxGjAYBgNVBAsMEUhlbGxvLUJvb3N0LUJlYXN0MRowGAYDVQQDDBFj
YS50ZXN0c2VydmVyLmxhbjAgFw0xOTEwMTEwMzM2MjNaGA8yMDY5MDkyODAzMzYy
M1owbzELMAkGA1UEBhMCQ0ExDzANBgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJp
bmNlLWNocmlzbWMxGjAYBgNVBAsMEUhlbGxvLUJvb3N0LUJlYXN0MRowGAYDVQQD
DBFjYS50ZXN0c2VydmVyLmxhbjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABN16
FJQf/p6ZiiENN8CHaNtrKbj1f+ckSB/q+tdKQR0Z/rLNVzDVCtY71GquxOPKMYeT
bcxzv+66VcadHs/6rIejYzBhMB0GA1UdDgQWBBSjMkDJkeNHMugsCDWP7XnQDDh5
vjAfBgNVHSMEGDAWgBSjMkDJkeNHMugsCDWP7XnQDDh5vjAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAgNIADBFAiEAxcb7effwCpp2
20zyVZmkQ9hu2WE+KdWhzXzt30v7yKgCIDsF5d5ILvtVv0zQh8IjiTtnq8cu0peJ
oVnUyef5DHda
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICNjCCAd2gAwIBAgICEAAwCgYIKoZIzj0EAwIwbzELMAkGA1UEBhMCQ0ExDzAN
BgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJpbmNlLWNocmlzbWMxGjAYBgNVBAsM
EUhlbGxvLUJvb3N0LUJlYXN0MRowGAYDVQQDDBFjYS50ZXN0c2VydmVyLmxhbjAg
Fw0xOTEwMTEwMzM2MjNaGA8yMDY5MDkyODAzMzYyM1owcDELMAkGA1UEBhMCQ0Ex
DzANBgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJpbmNlLWNocmlzbWMxGjAYBgNV
BAsMEUhlbGxvLUJvb3N0LUJlYXN0MRswGQYDVQQDDBJpY2EudGVzdHNlcnZlci5s
YW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASOCjSr9NF9qtrX3gT88n2XG6DL
D7AW88m0z19DUDlIOFqS2OntlxhdSmUPRpCTKwrD6zR6n72r1JfF5yENfr7Qo2Yw
ZDAdBgNVHQ4EFgQU+9C1jUFLM7vp6jZfYg0GoCYGMv8wHwYDVR0jBBgwFoAUozJA
yZHjRzLoLAg1j+150Aw4eb4wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8E
BAMCAYYwCgYIKoZIzj0EAwIDRwAwRAIgfcStNf0Y+UqT2e2oIVdyUmnOj4LX/zxj
YNDN1Mr83hgCIAUVcFu6Dv2UhHaqXd899WahplU4jYeXPdB1183MZBfa
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDDTCCArSgAwIBAgICEAEwCgYIKoZIzj0EAwIwcDELMAkGA1UEBhMCQ0ExDzAN
BgNVBAgMBlF1ZWJlYzEXMBUGA1UECgwOcHJpbmNlLWNocmlzbWMxGjAYBgNVBAsM
EUhlbGxvLUJvb3N0LUJlYXN0MRswGQYDVQQDDBJpY2EudGVzdHNlcnZlci5sYW4w
IBcNMTkxMDExMDMzNjI1WhgPMjA2OTA5MjgwMzM2MjVaMHIxCzAJBgNVBAYTAkNB
MQ8wDQYDVQQIDAZRdWViZWMxFzAVBgNVBAoMDnByaW5jZS1jaHJpc21jMRowGAYD
VQQLDBFIZWxsby1Cb29zdC1CZWFzdDEdMBsGA1UEAwwUaHR0cHMudGVzdHNlcnZl
ci5sYW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS+eLzOjNt/S4x/WKaGO9MW
mDp7Vc0QryHdaNAo7ZqiSJfaJGVKysrMLebv8BpWOT+v3mjHF54/KAFvvJve+AxC
o4IBODCCATQwCQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMCBkAwMwYJYIZIAYb4
QgENBCYWJE9wZW5TU0wgR2VuZXJhdGVkIFNlcnZlciBDZXJ0aWZpY2F0ZTAdBgNV
HQ4EFgQUP6Thn1V7n06kS1JKKxD7tw1ZG04wgZoGA1UdIwSBkjCBj4AU+9C1jUFL
M7vp6jZfYg0GoCYGMv+hc6RxMG8xCzAJBgNVBAYTAkNBMQ8wDQYDVQQIDAZRdWVi
ZWMxFzAVBgNVBAoMDnByaW5jZS1jaHJpc21jMRowGAYDVQQLDBFIZWxsby1Cb29z
dC1CZWFzdDEaMBgGA1UEAwwRY2EudGVzdHNlcnZlci5sYW6CAhAAMA4GA1UdDwEB
/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgNHADBEAiBJ
tQCBNRD+XUVkRtwoyPt8aDGoWYH+x7un6kDlBHfpfgIgWGswiE5yqQICEi+kHsfC
BXAAtOpNBJptmOmjRNnHpxY=
-----END CERTIFICATE-----
)###";

  const std::string key = R"###(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILlshWcQt03CJs2Rdo9QlmWM72MARgllwaZMLzfTdK4+oAoGCCqGSM49
AwEHoUQDQgAEvni8zozbf0uMf1imhjvTFpg6e1XNEK8h3WjQKO2aokiX2iRlSsrK
zC3m7/AaVjk/r95oxxeePygBb7yb3vgMQg==
-----END EC PRIVATE KEY-----
)###";

  const std::string dh = R"###()###";

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
