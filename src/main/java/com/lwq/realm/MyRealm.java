package com.lwq.realm;

import com.lwq.pojo.Admin;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import javax.xml.ws.BindingType;
import java.util.ArrayList;
import java.util.List;

public class MyRealm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        //1.获取认证通过的身份
        Admin primaryPrincipal = (Admin) principals.getPrimaryPrincipal();
        /**
         * 2.通过当前用户角色id 去 角色权限表中查询出当前用户的角色用户权限id
         *
         * 角色id 为 1  ---》对应权限id   （1,2,3,6,9）
         *
         * 2.1 再根据权限id去权限表中查询出所有权限对应的表达式
         *   1： user:list
         *   2:  user:insert
         *   3:  user:update
         *   6:  student:list
         *   9:  student:delete
         *
         */

        //模拟通过当前用户的角色查询出对应的权限的权限表达式
        //实际开发中不同的用户，拥有不同角色，不同觉得拥有权限不一样，最终查询权限表达式不一样
        List<String> permissions = new ArrayList<>();
        permissions.add("user:list");
        permissions.add("user:insert");
        permissions.add("student:list");

        //3. 创建授权信息对象
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        //4. 将查询出权限表达式设置给授权信息对象
        authorizationInfo.addStringPermissions(permissions);
        System.out.println("--------授权方法执行ok--------");
        return authorizationInfo;
    }
    /**
     * 认证方法，在此方法内完成认证逻辑
     * @param token 令牌，封装身份凭证（账号密码）
     * @return 认证信息对象，当前数据库中账号相关信息
     * @throws AuthenticationException
     */

    /**
     *  认证思路
     *  0，获取Token中的身份（账号）
     *
     *  1，注入AdminService adminService;
     *
     *  2,调用adminService根据账号去数据库中查询是否有次数据的方法
     *   Admin admin = adminService.selectByUsername(username);
     *   2.1 admin == null 数据库中没有此账号
     *    当前方法直接返回null ，Shiro底层就会抛出
     *      UnknownAccountException 账号不存在
     *   2.2 admin ！=null 数据库中有此账号
     *
     *   3，创建认证信息对象 AuthenticationInfo 将当前admin的账号密码作为参数传递给AuthenticationInfo信息对象
     *
     *   4，Shiro底层自动去获取AuthenticationInfo认证信息对象的密码和token的密码进行比对
     *     密码比成功，认证通过
     *     密码比对失败：会抛出
     *      IncorrectCredentialsException
     *
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("----begining...........----");
        //获取token中的数据
        String username = (String) token.getPrincipal();
        //模拟数据对比
        if (!"admin".equals(username)){
            return null;
        }
        //
        Admin admin = new Admin("admin","3733e87d5fe26530d9e85f211e65a4bb","qwer",1);
        //创建认证信息对象
        /**
         * SimpleAuthenticationInfo( principal,  credentials,realmName)
         * principal : 身份，就是当前账号 username
         * hashedCredentials ： 凭证（数据库查询出admin对象中对应的密码+加密后的）
         * ByteSource credentialsSalt 当前用户密码加密的salt
         * realmName ：realmName的名称，理论可以随意
         *
         * */
        ByteSource credentialsSalt = ByteSource.Util.bytes(admin.getSalt());

        return new SimpleAuthenticationInfo(admin,admin.getPassword(),credentialsSalt,this.getName());
    }
}
