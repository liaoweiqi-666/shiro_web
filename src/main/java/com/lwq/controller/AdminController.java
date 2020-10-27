package com.lwq.controller;

import com.sun.org.apache.xpath.internal.operations.Mod;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;

@Controller
@RequestMapping("/admin")
public class AdminController {

    @RequestMapping("/loginError")
    public String loginError(HttpServletRequest request, Model model){
        //获取错误的信息
        String shiroLoginFailure = (String) request.getAttribute("shiroLoginFailure");
        System.out.println("shiroLoginFailure = " + shiroLoginFailure);
        //认证时，判断是否为空，
        if (shiroLoginFailure != null){
            if (UnknownAccountException.class.getName().equals(shiroLoginFailure)){
                System.out.println("用户名不存在！！！");
                model.addAttribute("errorMsg","用户名不存在");
            }if (IncorrectCredentialsException.class.getName().equals(shiroLoginFailure)){
                System.out.println("密码错误！！");
                model.addAttribute("errorMsg","密码错误");
            }
        }

        return "forward:/admin/loginPage";
    }

    //登录页面
    @RequestMapping("/loginPage")
    public String loginPage(){
        return "login";
    }


}
