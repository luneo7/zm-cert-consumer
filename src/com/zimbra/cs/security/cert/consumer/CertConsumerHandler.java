package com.zimbra.cs.security.cert.consumer;

import com.zimbra.common.account.Key;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraCookie;
import com.zimbra.cs.account.*;
import com.zimbra.cs.extension.ExtensionHttpHandler;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.service.AuthProvider;
import com.zimbra.cs.servlet.util.AuthUtil;
import org.bouncycastle.asn1.x509.GeneralName;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

/**
 * Created by lucasferreira on 8/18/17.
 */
public class CertConsumerHandler extends ExtensionHttpHandler {

  private static final String CLIENT_CERTIFICATE_HEADER = "X-Client-Certificate";

  private X509Certificate extractClientCertificate(HttpServletRequest request) throws UnsupportedEncodingException {
    X509Certificate[] certificateChainObj = null;

    CertificateFactory certificateFactory = null;
    try {
      certificateFactory = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      ZimbraLog.extensions.warn("Could not extract certificate from request", e);
      throw new RuntimeException(e);
    }

    String certificateHeader = request.getHeader(CLIENT_CERTIFICATE_HEADER);

    if (certificateHeader == null) {

      certificateChainObj = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

      if (certificateChainObj == null) {
        ZimbraLog.extensions.warn("Client certificate attribute is null! Check if you are behind a proxy server that takes care about the " +
                "client authentication already. If so, set the property 'client.authentication.behind.proxy' to true and " +
                "make sure the proxy sets the HTTP header 'X-Client-Certificate' appropriately to the sent client certificate");
        return null;
      }
    } else {

      certificateHeader = URLDecoder.decode(certificateHeader, "ISO-8859-11");

      String certificateContent = certificateHeader.replaceAll("(?<!-----BEGIN|-----END)\\s+", System.lineSeparator())
          .replaceAll("\\t+", System.lineSeparator());

      if(ZimbraLog.extensions.isDebugEnabled()) {
        ZimbraLog.extensions.debug("found this certificate in the " + CLIENT_CERTIFICATE_HEADER + " header (after whitespace replacement): " + certificateContent);
      }

      try {
        certificateChainObj = new X509Certificate[1];
        certificateChainObj[0] = (X509Certificate) certificateFactory
            .generateCertificate(new ByteArrayInputStream(certificateContent.getBytes("ISO-8859-11")));
      } catch (CertificateException e) {
        throw new RuntimeException("could not extract certificate from request", e);
      } catch (UnsupportedEncodingException e) {
        throw new RuntimeException("could not extract certificate from request with encoding " +
            "ISO-8859-11",e);
      }

    }

    return certificateChainObj[0];
  }

  String getSubjectAltNameRfc822Name(X509Certificate cert) {
    Collection<List<?>> generalNames = null;
    try {
      generalNames = cert.getSubjectAlternativeNames();
    } catch (CertificateParsingException e) {
      ZimbraLog.extensions.warn("unable to get subject alternative names", e);
    }

    if (generalNames == null) {
      return null;
    }

    for (List<?> generalName : generalNames) {
      Integer tag = (Integer) generalName.get(0);
      if (GeneralName.rfc822Name == tag.intValue()) {
        String value = (String) generalName.get(1);
        return value;
      }
    }

    return null;
  }

  private static AuthToken getZimbraAuthToken(HttpServletRequest req, boolean isAdminRequest) {
    String encodedToken = getCookieValue(req, ZimbraCookie.authTokenCookieName(isAdminRequest));
    if (encodedToken == null)
      return null;
    AuthToken authToken;
    try {
      authToken = AuthProvider.getAuthToken(encodedToken);
    } catch (AuthTokenException e) {
      // invalid token, no problem
      return null;
    }
    return authToken.isExpired() ? null : authToken;
  }

  private static String getCookieValue(HttpServletRequest req, String cookieName) {
    Cookie cookies[] = req.getCookies();
    if (cookies != null) {
      for (Cookie cookie : cookies) {
        if (cookie.getName().equals(cookieName))
          return cookie.getValue();
      }
    }
    return null;
  }

  @Override
  public String getPath() {
    return "/cert/consumer";
  }


  @Override
  public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
    doPost(req, resp);
  }

  @Override
  public void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
    processCert(req, resp);
  }

  private String appendIgnoreLoginURL(String redirectUrl) {
    if (!redirectUrl.endsWith("/")) {
      redirectUrl = redirectUrl + "/";
    }
    return redirectUrl + AuthUtil.IGNORE_LOGIN_URL;
  }

  private void processCert(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    X509Certificate cert =  extractClientCertificate (req);

    resp.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    resp.setHeader("Pragma", "no-cache");
    resp.setDateHeader("Expires",0);

    if (cert != null) {
      String email = getSubjectAltNameRfc822Name(cert);
      String reqParam = req.getParameter("admin");

      boolean isAdminRequest = (reqParam != null && reqParam.equals("true"));

      try {
        Provisioning prov = Provisioning.getInstance();
        AuthToken authToken = getZimbraAuthToken(req, isAdminRequest);
        Account account;

        if (authToken == null) {
          account = prov.get(Key.AccountBy.name, email);

          // add a zimbra cookie to the response
          authToken = AuthProvider.getAuthToken(account, isAdminRequest);
          authToken.encode(resp, isAdminRequest, req.getScheme().equals("https"));
        } else {
          account = authToken.getAccount();
        }

        // redirect to the correct URL
        Server server =  account.getServer();
        if (server == null) {
          throw new ServletException("Server not found corresponding to account " + account.getName());
        }

        String redirectUrl = appendIgnoreLoginURL(isAdminRequest ? server.getAdminURL() : server.getMailURL());

        resp.sendRedirect(redirectUrl);

      } catch (ServiceException e) {
        ZimbraLog.extensions.warn("Unexpected error after having verified certificate", e);
        throw new ServletException(e.getMessage());
      }
    }
    else {
      String redirect = req.getRequestURL().toString();
      redirect = redirect.substring(0,redirect.indexOf("/service"));
      String query = req.getQueryString();
      if(query != null){
        redirect = redirect + "?" + query;
      }
      resp.sendRedirect(redirect);
    }
  }
}
