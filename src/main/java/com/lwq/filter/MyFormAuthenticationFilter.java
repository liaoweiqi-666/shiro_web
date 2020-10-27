package com.lwq.filter;

import com.lwq.pojo.Admin;
import org.apache.juli.OneLineFormatter;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class MyFormAuthenticationFilter extends FormAuthenticationFilter {

    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response) throws Exception {
        //清除Session中的保存的数据
        WebUtils.getAndClearSavedRequest(request);
        return super.onLoginSuccess(token, subject, request, response);
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
       //从请求中获取shiro的主体
        Subject subject = getSubject(request, response);
        //从主体中获取shiro框架的session
        Session session = subject.getSession();
        //如果主体没有认证则session中认证
        if (!subject.isAuthenticated()&&subject.isRemembered()){
       //获取主体的身份（从cookie中获取）
            Admin principal = (Admin) subject.getPrincipal();
            //将认证身份信息共享到session中，session名称可以随意改，底层按照类型自动获取
            session.setAttribute("admin",principal);
        }
        return subject.isAuthenticated() || subject.isRemembered();
    }
}
