package com.zimbra.cs.security.cert.consumer;

import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.extension.ExtensionDispatcherServlet;
import com.zimbra.cs.extension.ExtensionException;
import com.zimbra.cs.extension.ZimbraExtension;

/**
 * Created by lucasferreira on 8/18/17.
 */
public class CertConsumerExtension implements ZimbraExtension {

  public CertConsumerExtension() {
    // TODO Auto-generated constructor stub
  }

  public String getName() {
    return "certconsumer";
  }

  public void init() throws ExtensionException, ServiceException {
    ExtensionDispatcherServlet.register(this, new CertConsumerHandler());
  }

  public void destroy() {
    ExtensionDispatcherServlet.unregister(this);
  }
}
