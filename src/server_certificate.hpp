//
// Copyright (c) 2016-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef BOOST_BEAST_EXAMPLE_COMMON_SERVER_CERTIFICATE_HPP
#define BOOST_BEAST_EXAMPLE_COMMON_SERVER_CERTIFICATE_HPP

#include <boost/asio/buffer.hpp>
#include <boost/asio/ssl/context.hpp>
#include <cstddef>
#include <memory>

/*  Load a signed certificate into the ssl context, and configure
    the context for use with a server.

    For this to work with the browser or operating system, it is
    necessary to import the "Beast Test CA" certificate into
    the local certificate store, browser, or operating system
    depending on your environment Please see the documentation
    accompanying the Beast certificate for more details.
*/
inline
void
load_server_certificate(boost::asio::ssl::context& ctx)
{
    /*
        openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 9999 -out certificate.pem -subj "/C=CA/ST=Quebec/L=Montreal/O=prince-chrismc/OU=Hello-Boost-Beast/CN=https.testserver.lan"
    */

    const std::string cert = R"###(-----BEGIN CERTIFICATE-----
MIID7TCCAtWgAwIBAgIUNawTVfPRT7MAbtZZiEJ1luaCtLgwDQYJKoZIhvcNAQEL
BQAwgYUxCzAJBgNVBAYTAkNBMQ8wDQYDVQQIDAZRdWViZWMxETAPBgNVBAcMCE1v
bnRyZWFsMRcwFQYDVQQKDA5wcmluY2UtY2hyaXNtYzEaMBgGA1UECwwRSGVsbG8t
Qm9vc3QtQmVhc3QxHTAbBgNVBAMMFGh0dHBzLnRlc3RzZXJ2ZXIubGFuMB4XDTE5
MDkxODAwNDYxNloXDTQ3MDIwMjAwNDYxNlowgYUxCzAJBgNVBAYTAkNBMQ8wDQYD
VQQIDAZRdWViZWMxETAPBgNVBAcMCE1vbnRyZWFsMRcwFQYDVQQKDA5wcmluY2Ut
Y2hyaXNtYzEaMBgGA1UECwwRSGVsbG8tQm9vc3QtQmVhc3QxHTAbBgNVBAMMFGh0
dHBzLnRlc3RzZXJ2ZXIubGFuMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAxM2va5Yb+pS6yB+DztCrStpHWTokBeeYXrTNQoMdVxMWo1q/4HJ0rrsWxuTU
ZipcjTsBmIqmFrO6C6l+CC2SXAYT3YVQGD3A3v4z6ORg9rkOHMGxBrAtjR7Jw46k
+6MWTR8/RHmC+O8+8fvsQfwoEPP3haxOc4NYjjtMfeN9x8knJOxHq1zdCLUYYd+p
wgqWWW4q8V2YeaYr4GPCZ7OR0gNfJoN/vudZzAbQSQe5N0jzTka304Ajxd9f3uqc
QcxnL8RRYFPRo3OTJXcByo3aJyLcg3zel1EB9LajOCZs6yG6Cd8Ror7eDN86I3G4
cyjQm9Ed3id9SGGIcqx1SMjONwIDAQABo1MwUTAdBgNVHQ4EFgQUsUKo3HIcywGh
FKen16lRPeabs80wHwYDVR0jBBgwFoAUsUKo3HIcywGhFKen16lRPeabs80wDwYD
VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAXTkz+SwQaR1QTdW58coL
dF8CFXLQmF8UIViblL0eGRf3Lj0EE7tLH042z6aqRaaLrlVFfopnsXtaxLQcMLCK
YCUfTpYpwCLtotZMZH7QKaW+zn4vk4fdA3B2O+bwNJtRTalNRTtc3DefZItnrPVt
NKhOUx9rWV1uTmfa7nIPg6Q+ivCfJGQ4C6i/voEoJP+vp8ulcfcpIDvMFcNIt/kh
k7E/gBwG6OmDTixTnGKH/8pdyoxRZ7eKZCFmv9ibmfRbYdLQYSgEgLbxF89JQDXJ
w2FpnEAUeba4NqazNyQqbcgobkudqS2Da/m5A1FhC57nPQ58LlAMWOD+eopZu8bh
cg==
-----END CERTIFICATE-----
)###";

    const std::string key = R"###(-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDEza9rlhv6lLrI
H4PO0KtK2kdZOiQF55hetM1Cgx1XExajWr/gcnSuuxbG5NRmKlyNOwGYiqYWs7oL
qX4ILZJcBhPdhVAYPcDe/jPo5GD2uQ4cwbEGsC2NHsnDjqT7oxZNHz9EeYL47z7x
++xB/CgQ8/eFrE5zg1iOO0x9433HySck7EerXN0ItRhh36nCCpZZbirxXZh5pivg
Y8Jns5HSA18mg3++51nMBtBJB7k3SPNORrfTgCPF31/e6pxBzGcvxFFgU9Gjc5Ml
dwHKjdonItyDfN6XUQH0tqM4JmzrIboJ3xGivt4M3zojcbhzKNCb0R3eJ31IYYhy
rHVIyM43AgMBAAECggEBAJd2TVmZr3LM4GuAhaq3wfzbvSmYq3y33vaUY5ya2AvZ
rwSNpTqSG+cWKdNs7WKrm4s+LF4/5s92ButOyKZ2nDuimctU/G2LqVJ1hXHpwg5g
IdJT53BkSspfNZ0BvUvFGjbEo6aJdhkr19/YqN2nuRZDDO6dy8ru/UqJrLb+TCFi
/sKmtQfh5otYRXxNGq8kUXL3NuQR6cK5J+zHVL1oq59PzqKSzNlUPH5cP3XQB5ve
ichS7o3cFpM3Nf9cs8jj9WxvhXEI+53VyL/ExEeF7JsmmU+vbgBlzWGdB1DLr6ZE
r78Lm8oVMgd6LCebMZSstJLmYrolvoawNt1LAfb5WLECgYEA6Bdgb7TsOmu/BjTs
PpDEuoFqFGHJQRsSuK0RvJ8B7PI4l3/wKuinKewPsf4MQtEe3kr4JNQ+ERbkAxWD
x3D0mktF/KuT3tPyE4atYDqki7kQkBhWnTpQTvVPmyquI4DfnGJ/WljOHg8ux9Fv
6Lzp4xi4KoQwh4xtJcmDWZ8YTLUCgYEA2RO17nwilNeJ98zY/Y9BsZ50vEAXqqfh
5OxePzcKA5qn8RCtbC8JZHRUZcGUc8pvm8tmvU2CbbjPKJOrIdBTme6hLh52ATX2
tcS0UEfwbohJHKqcNmF1xc+B8oiBiDrsDhAoFXZBSbzX2EIx6+RXJFR1Y2BBhrrf
9rTivpunbrsCgYEA2tF3dbpxYl9Fmfd5qT9ai7EKL69GTSDWVNGvwFN2QEza+FOC
PyJcwNS0s48fRjvdy52JOUf2QKyBSzsUpIwlwfcoRCIMZ3ESckBu5CRGEQnpyMF5
oAFjyB3W8SebSRPvP4VKJwdFRefwpiobRaYfKaKbuFIrYxENsyu7sFqkUWUCgYEA
iRQqWewnxkgJxuKj0BKr0GcYnlv21fxn6LDenxq5hycdkFwQt3VIgBf5x7wja69V
JVOfkEEm8PS4VI5TjenJMTaAr+fqar9SCNyrZNrY2GPVj3WpaanHvl9YVviem5Fh
yUuolEz104Od5eF/NtAdu0JeUp/RISxXC6qUWPtgEssCgYEAhUJ3+gqqgGLM6TWp
M3GuE5qt/LdjsK9iZ3fkSpyjw5IEZnJZWWC/uEqFtZRtgpMGtmUOQPNy9Odef54I
W2YLdFkfy9QjUseiBP/LO3tNGd8QHh9XPWeLIDwXvtbHfTg92ZLzGA+15aSdbPY3
5k7RrIS7P0ZnII6tfYrTG0jOtPI=
-----END PRIVATE KEY-----
)###";

    const std::string dh =
        "-----BEGIN DH PARAMETERS-----\n"
        "MIIBCAKCAQEArzQc5mpm0Fs8yahDeySj31JZlwEphUdZ9StM2D8+Fo7TMduGtSi+\n"
        "/HRWVwHcTFAgrxVdm+dl474mOUqqaz4MpzIb6+6OVfWHbQJmXPepZKyu4LgUPvY/\n"
        "4q3/iDMjIS0fLOu/bLuObwU5ccZmDgfhmz1GanRlTQOiYRty3FiOATWZBRh6uv4u\n"
        "tff4A9Bm3V9tLx9S6djq31w31Gl7OQhryodW28kc16t9TvO1BzcV3HjRPwpe701X\n"
        "oEEZdnZWANkkpR/m/pfgdmGPU66S2sXMHgsliViQWpDCYeehrvFRHEdR9NV+XJfC\n"
        "QMUk26jPTIVTLfXmmwU0u8vUkpR7LQKkwwIBAg==\n"
        "-----END DH PARAMETERS-----\n";

    ctx.set_options(
        boost::asio::ssl::context::default_workarounds)
                //  boost::asio::ssl::context::no_sslv2 |
                //  boost::asio::ssl::context::no_sslv3 |
                //  boost::asio::ssl::context::no_tlsv1 |
        /* boost::asio::ssl::context::single_dh_use)*/;

    ctx.use_certificate(
        boost::asio::buffer(cert.data(), cert.size()),
        boost::asio::ssl::context::file_format::pem);

    ctx.use_private_key(
        boost::asio::buffer(key.data(), key.size()),
        boost::asio::ssl::context::file_format::pem);

    // ctx.use_tmp_dh(
    //     boost::asio::buffer(dh.data(), dh.size()));
}

#endif
