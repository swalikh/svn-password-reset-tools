package com.swalikh.resetpasswd.controller;

import com.swalikh.resetpasswd.component.ConfigService;
import com.swalikh.resetpasswd.encoder.Md5Encoder;
import com.swalikh.resetpasswd.exception.Result;
import com.swalikh.resetpasswd.service.MapFileService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

@Controller
public class PasswdController {

    private static final Logger LOGGER = LoggerFactory.getLogger(PasswdController.class);

    @Autowired
    private MapFileService fileService;

    @Autowired
    private ConfigService configService;

    @RequestMapping(value = "/resetPass",method = RequestMethod.POST)
    public ModelAndView resetPass(HttpServletRequest request,String username, String originPass,String pass, String rePass) throws Exception {
        // 1.记录日志 IP 用户名 密码等
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
        String time = format.format(new Date());
        String ipaddr = request.getRemoteAddr();
        LOGGER.info("{}  用户{}尝试修改密码  新密码：{}  重复新密码：{}  IP地址：{}",time,username,pass,rePass,ipaddr);
        Result result = validateParams(username,pass,rePass,originPass);
        // 2.校验数据
        if(result.getStatus() == Result.OK){
            // 3.保存数据
            fileService.save(username,pass);
            LOGGER.info("{}  用户{}修改密码成功！  新密码为:{}  IP地址：{}",time,username,pass,ipaddr);
            return successView(pass);
        } else {
            LOGGER.info("{}  用户{}尝试修改密码失败！  原因为:{}  IP地址：{}",time,username,result.getMsg(),ipaddr);
            return errorView(result.getMsg());
        }
    }

    @RequestMapping(value = "/",method = RequestMethod.GET)
    public ModelAndView index() throws IOException {
        ModelAndView view = new ModelAndView("index");
        try {
            String svn_url = configService.getConfig(ConfigService.key_current_svn_url_address);

            view.addObject("svnUrl",svn_url);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            return view;
        }
    }

//    校验数据的合法性
    private Result validateParams(String username, String pass, String rePass, String origin_input) throws Exception {
        if(username == null ||pass == null || rePass ==null || username.equals("") ||pass.equals("") || rePass.equals("")){
            return Result.err("账号或密码不能为空");
        }
        // 2.看该账号找不找的到
        Map<String,String> map = fileService.getPassMap();
        String originPass = map.get(username);
        String sss = map.remove(username);
        LOGGER.info("原来的账号为：{} 密码为：{}",username,originPass);
        if( sss == null || originPass.equals("")){
            return Result.err("没有此用户:"+username+"！ 请联系管理员王磊！");
        }

        // 3.校验原密码是否合法
        String passTrue = Md5Encoder.encodeByWithSalt(username,origin_input,Md5Encoder.getSalt(originPass));
        if(!passTrue.equals(originPass)){
            return Result.err("原密码错误,请重试或请联系管理员王磊！");
        }
        // 3.看两次密码是否一致
        if(!pass.equals(rePass)){
            return Result.err("两次密码输入不一致！请重试！");
        }
        // 4.密码长度至少6位
        if(!(pass.length()>=6)){
            return Result.err("密码的长度至少6位！请重试！");
        }
        return Result.ok("");
    }

    private ModelAndView errorView(String error) {
        ModelAndView view = new ModelAndView("error");
        view.addObject("error",error);
        return view;
    }

    private ModelAndView successView(String newPassword) {
        ModelAndView view = new ModelAndView("success");
        view.addObject("newPass",newPassword);
        return view;
    }


}
