package com.i2max.hello;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.tomcat.util.codec.binary.Base64;
import org.opensaml.xml.io.MarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.i2max.saml.SAMLWrapper;

@Controller
@EnableAutoConfiguration
public class SampleController {
	private static final Logger logger = LoggerFactory.getLogger(SampleController.class);

	// @ResponseBody : body 그대로 출력.
	@RequestMapping("/")
	@ResponseBody
	public String sso() {
		return "SP(Service Provider, Salesforce, Marketing Cloud 등)을 통해 /sso/init 를 호출하세요.~";
	}

	// SP쪽에서 Initial URL로 POST 방식으로 보낸다.
	@RequestMapping(value = "/sso/init", method = RequestMethod.POST)
	public String ssoInit() {
		return "redirect:/sso/login";
	}	

	@RequestMapping("/sso/login")
	public String ssoLogin() {
		return "sso/login";
	}
	
	@RequestMapping("/sso/logout")
	public String ssoLogout(HttpServletRequest req, HttpServletResponse res, Model model) {
		req.getSession().invalidate();
		
		return "sso/login";
	}
	
	@RequestMapping("/sso/loginOK")
	public String loginOK(HttpServletRequest req, HttpServletResponse res, Model model) throws MarshallingException {
    	String loginEmail = req.getParameter("email");
    	logger.debug("loginEmail ::: {}", loginEmail);
    	
    	req.getSession().setAttribute("email", loginEmail);
    	
    	SAMLWrapper samlWrapper = new SAMLWrapper(loginEmail);
    	
    	String signedSAML = samlWrapper.getSAML();// for debuging
    	String samlResponse = Base64.encodeBase64String(signedSAML.getBytes());; // base64 encoded string of signedSAML
    	String relayState = req.getParameter("relayState");
    	logger.debug("relayState ::: {}", relayState);
    	
    	model.addAttribute("recipientURL", SAMLWrapper.RECIPIENT_URL); // for debug
    	model.addAttribute("signedSAML", signedSAML);
    	model.addAttribute("samlResponse", samlResponse);
    	model.addAttribute("relayState", relayState);
    	
    	return "sso/loginOK";
	}

	// local test
	@RequestMapping(value = "/ttt", method = RequestMethod.PUT)
	@ResponseBody
	public Object homePut() {
		Map<String, String> map = new HashMap<String, String>();
		map.put("message", "put method call.");

		return map;
	}
	@RequestMapping(value = "/ttt", method = RequestMethod.GET)
	@ResponseBody
	public Object homeGet() {
		Map<String, String> map = new HashMap<String, String>();
		map.put("message", "get method call.");
		
		return map;
	}
}