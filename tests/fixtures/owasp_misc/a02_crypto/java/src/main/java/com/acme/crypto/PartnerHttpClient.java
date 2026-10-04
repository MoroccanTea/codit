package com.acme.crypto;

import java.net.http.HttpClient;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PartnerHttpClient {

    @Bean
    public HttpClient legacyPartnerClient() throws Exception {
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                // codit-expect: CWE-295 trust manager accepts every server certificate
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new SecureRandom());



        // codit-expect: CWE-295 hostname verification disabled globally
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        return HttpClient.newBuilder().sslContext(ctx).connectTimeout(Duration.ofSeconds(5)).build();
    }



    @Bean
    public HttpClient partnerClient() throws Exception {
        // codit-safe: CWE-295 default SSLContext (JVM trust store + hostname verification)
        return HttpClient.newBuilder().sslContext(SSLContext.getDefault()).connectTimeout(Duration.ofSeconds(5)).build();
    }
}
