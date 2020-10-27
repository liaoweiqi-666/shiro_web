package com.lwq.controller;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/user")
public class UserController {

    @RequestMapping("list")
    @RequiresPermissions("user:list")
    @ResponseBody
    public String list(){
        return "wangwang";
    }

    @RequestMapping("/insert")
    @ResponseBody
    @RequiresPermissions("user:insert")
    public String insert(){
        return "success add!!!";
    }
}
