package org.cboard.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.alibaba.fastjson.JSON;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.io.IOException;

@Controller
public class LoginController {

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String loginPage() {
        return "login";
    }

    private String getPrincipal(){
        String userName = null;
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (principal instanceof UserDetails) {
            userName = ((UserDetails)principal).getUsername();
        } else {
            userName = principal.toString();
        }
        return userName;
    }

    @RequestMapping(value="/timeout")
    public void timeOut(HttpServletRequest req,HttpServletResponse resp) throws IOException {
        if(req.getHeader("X-Requested-With") != null && "XMLHttpRequest".equalsIgnoreCase(req.getHeader("X-Requested-With"))){
            resp.setStatus(401);
            resp.getWriter().print("<result><code>err_timeout</code><message>session超时</message></result>");
            resp.getWriter().flush();
        }else{
            resp.sendRedirect("/login.do");
        }
    }
}