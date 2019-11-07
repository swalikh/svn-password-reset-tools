package com.swalikh.resetpasswd.component;


import com.swalikh.resetpasswd.controller.PasswdController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;

@Component
public class ConfigService {

    private static final Logger LOGGER = LoggerFactory.getLogger(PasswdController.class);

//    默认值
    public static final String dir_name= "SVN修改密码配置文件";
    public static final String config_name= "config.txt";
    public static final String configfullPath= dir_name+File.separator+config_name;


    //  key-value
    public static final String key_current_svn_url_address= "current_svn_url_address";
    public static final String     current_svn_url_address= "";

    public static final String key_password_file_path= "password_file_path";
    public static final String     password_file_path= "";



    public ConfigService() throws IOException {
        File dir = new File("SVN修改密码配置文件");
        if(!dir.exists()){
            dir.mkdirs();
        }
        File config = new File(dir_name+File.separator+config_name);
        if(!config.exists()){
            Properties properties = new Properties();
            properties.setProperty(key_current_svn_url_address,current_svn_url_address);
            properties.setProperty(key_password_file_path,password_file_path);
            properties.save(new FileOutputStream(config),"reset password by self @nlelpct2019");
        }
    }

    public String getConfig(String key) throws IOException {
        Properties pro = new Properties();
        pro.load(new FileReader(new File(configfullPath)));
       return (String) pro.get(key);
    }

    public String getHtpasswdPath() throws IOException {
        String filePath = System.getProperty("user.dir");
       String path = filePath+File.separator+"htpasswd";
       String config_path =  getConfig(key_password_file_path);
        if(config_path != null && !config_path.equals("")){
            path = config_path;
        }
        System.err.println("配置文件中的路径为:"+getConfig(key_password_file_path));
        System.err.println("系统默认的路径为  :"+filePath+File.separator+"htpasswd");
        System.err.println("实际使用的路径为  :"+path);
        return path;
    }



}
