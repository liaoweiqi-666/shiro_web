package com.lwq.config;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
import com.lwq.filter.MyFormAuthenticationFilter;
import com.lwq.realm.MyRealm;
import com.sun.tracing.ProbeName;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.handler.SimpleMappingExceptionResolver;

import javax.servlet.Filter;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;


@Configuration
public class ShiroConfig {

    //配置shiro发言，让thymeleaf支持shiro标签
    @Bean
    public ShiroDialect shiroDialect(){
        return new ShiroDialect();
    }


    /**
     * Shiro框架和Spring基础配置对象细节配置
     * @return
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(){
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();

        Map<String, Filter> filters = new HashMap<>();

        //将自定义的过滤器作为默认过滤器
        filters.put("logout",logoutFilter());
        filters.put("authc",myFormAuthenticationFilter());

        /*设置自定义过滤器*/
        shiroFilterFactoryBean.setFilters(filters);

        //配置安全管理器
        shiroFilterFactoryBean.setSecurityManager(securityManager());
        //配置页面认证失败后，跳转页面，共享认证失败的信息（必须是一个控制器请求转让的地址）
        shiroFilterFactoryBean.setLoginUrl("/admin/loginError");
        //配置认证成功后，一般调到后台首页
        shiroFilterFactoryBean.setSuccessUrl("/index");
        //配置认证成功后访问没有权限的页面是，提示页面（注解配置时权限时，必须放到templates下）
        shiroFilterFactoryBean.setUnauthorizedUrl("unauthorized.html");

        /**
         * 配置Shiro框架的过滤器链 ?为什么要配置过滤器链
         *
         * Shiro框架和web项目集成以后，所有的项目请求都先经过Shiro框架过滤器
         * 因为请求资源是各种各样的，所以需要将其分类
         *  1，直接放行 - 静态资源，（css，js，图片）
         *  2，需要认证但是不需要权限（登录）-后台首页
         *  3，既需要认证又需要权限的资源  （admin/list,student/insert,teacher/update ....）
         *
         *  Shiro针对这些不同资源类型编写多种过滤器规则（11个），我们开发者只需要使用这个对应的过滤器，那就就可以完成对应过滤规则处理
         *   别名    全限定名
         *   anon	org.apache.shiro.web.filter.authc.AnonymousFilter
         *          匿名过滤器，经过此过滤器的资源不要认证也不需要权限，直接放行
         *   authc	org.apache.shiro.web.filter.authc.FormAuthenticationFilter
         *          表单认证过滤器，如果匹配到此过滤器，说明必须要认证，如果没有认证
         *           会跳转到认证失败页面:shiroFilterFactoryBean.setLoginUrl("/admin/loginError");
         *
         *          底层判断逻辑
         *           从当前Session中获取认证成功以后身份信息
         *           1，没有：当前没有认证（登录）跳转认证失败页面
         *           2，有：放行跳转的资源
         *
         *           logout	org.apache.shiro.web.filter.authc.LogoutFilter
         *          退出认证过滤器，会自动清空Session和Cookie中的数据，并且跳转到项目的根路 /
         *   perms	org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter
         *          权限授权过滤器
         *          使用方法，只需要将访问的地址设置对应的权限表达式
         *          如： user:list,student:list,user:insert....
         *          Shiro底层就会执行自定义Reaml-->MyRealm 中的 -》 doGetAuthorizationInfo
         *          进行授权判断处理
         *
         *          1，有对应权限：放行
         *          2，没有权限：默认跳转没有访问权限的页面去
         *               shiroFilterFactoryBean.setUnauthorizedUrl("/unauthorized.html");
         *
         *          语法： perms[权限表达式]
         *
         *          缺陷：需要将每一个访问资源都配置一个权限表达式，如果项目有1000个请求，此处配置1000个权限代码
         *             会导致项目配置文件非常臃肿
         *
         *           解决方案：使用注解，将注解贴在每一个需要用拥有权限的SpringMVC控制器方法（增删改查操作）
         */
        //使用别名就相当于使用此过滤器,访问资源匹配过滤器从上到下匹配，如果匹配成功，就不会继续向下匹配了

        //创建过滤器链Map集合
        Map<String, String> chainMap = new HashMap<>();

        //匿名过滤器配置
        chainMap.put("/js/**","anon");
        chainMap.put("/css/**","anon");
        chainMap.put("/images/","anon");
        chainMap.put("/admin/loginPage","anon");

        //退出登录过滤器
        chainMap.put("/exit","logout");
        /*记住我以后的过滤器*/
        /*chainMap.put("/index","user");*/
        //权限授权过滤器
//        chainMap.put("user:list","perms[user:list]");
//        chainMap.put("student:list","perms[student:list]");
        //配置表单认证过滤器
        chainMap.put("/**","authc");

        shiroFilterFactoryBean.setFilterChainDefinitionMap(chainMap);

        return shiroFilterFactoryBean;

    }
    //核心对象。安全管理器
    @Bean
    public DefaultWebSecurityManager securityManager(){
        DefaultWebSecurityManager defaultWebSecurityManager = new DefaultWebSecurityManager();
        //注入myRealm
        defaultWebSecurityManager.setRealm(myRealm());
        //配置缓存
        defaultWebSecurityManager.setCacheManager(cacheManager());
        //配置会话管理器
        defaultWebSecurityManager.setSessionManager(sessionManager());
        //配置记住我管理器
        defaultWebSecurityManager.setRememberMeManager(rememberMeManager());

        return defaultWebSecurityManager;
    }

    //创建对SpringMVC抛出异常处理解析器
    @Bean
    public SimpleMappingExceptionResolver simpleMappingExceptionResolver(){
        Properties properties = new Properties();
        /*配置符合 SpringBoot的 视图解析前后缀规则*/
        properties.put("org.apache.shiro.authz.UnauthorizedException","/unauthorized");
        SimpleMappingExceptionResolver simpleMappingExceptionResolver = new SimpleMappingExceptionResolver();
        simpleMappingExceptionResolver.setExceptionMappings(properties);

        return simpleMappingExceptionResolver;
    }



    //设置Shiro框架对注解支持
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(){
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        //设置安全管理器
        advisor.setSecurityManager(securityManager());

        return advisor;
    }

    /*设置Spring框架支持集成其他框架可以使用AOP*/
    @Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator(){
        DefaultAdvisorAutoProxyCreator creator = new DefaultAdvisorAutoProxyCreator();
        creator.setProxyTargetClass(true);

        return creator;
    }

    //配置记住我管理器
    @Bean
    public RememberMeManager rememberMeManager(){
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
        //设置cookie对象
        cookieRememberMeManager.setCookie(cookie());

        return cookieRememberMeManager;
    }

    //创建Cookie
    @Bean
    public Cookie cookie(){
        SimpleCookie simpleCookie = new SimpleCookie();
        //设置cookie时间
        simpleCookie.setMaxAge(60*60*24*10);
        //设置cookie名称
        simpleCookie.setName("rememberMe");

        return simpleCookie;
    }

    //配置会话管理器
    @Bean
    public SessionManager sessionManager(){
        DefaultWebSessionManager defaultWebSessionManager = new DefaultWebSessionManager();
        //单位毫秒
        defaultWebSessionManager.setGlobalSessionTimeout(10*60);

        return defaultWebSessionManager;
    }

    //配置缓存
    @Bean
    public CacheManager cacheManager(){
        EhCacheManager ehCacheManager = new EhCacheManager();

        return ehCacheManager;
    }

    //自定义realm
    @Bean
    public MyRealm myRealm(){
        MyRealm myRealm = new MyRealm();
        //设置realm的凭证匹配器
        myRealm.setCredentialsMatcher(credentialsMatcher());

        return myRealm;
    }

    //创建凭证匹配器
    @Bean
    public CredentialsMatcher credentialsMatcher(){
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("md5");
        matcher.setHashIterations(3);
        return matcher;
    }

    //重新创建退出认证过滤器 ,注意：不要写@Bean注解，普通方法
    public LogoutFilter logoutFilter(){
        System.out.println("ShiroConfig.logoutFilter");
        LogoutFilter logoutFilter = new LogoutFilter();
        logoutFilter.setRedirectUrl("/admin/loginPage");
        System.out.println("hello,shiri web");
        return logoutFilter;
    }

    //使用自定义表单认证过滤器8
    public MyFormAuthenticationFilter myFormAuthenticationFilter(){
        MyFormAuthenticationFilter myFormAuthenticationFilter = new MyFormAuthenticationFilter();
        return myFormAuthenticationFilter;
    }

}
