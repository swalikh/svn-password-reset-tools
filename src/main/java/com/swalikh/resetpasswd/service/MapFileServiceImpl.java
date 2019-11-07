package com.swalikh.resetpasswd.service;

import com.swalikh.resetpasswd.component.ConfigService;
import com.swalikh.resetpasswd.controller.PasswdController;
import com.swalikh.resetpasswd.encoder.Md5Encoder;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

@Service
public class MapFileServiceImpl implements MapFileService {

    private static final Logger LOGGER = LoggerFactory.getLogger(PasswdController.class);

    @Autowired
    private ConfigService configService;

    @Override
    public Map<String, String> getPassMap() throws IOException {
        String htpasswdPath = configService.getHtpasswdPath();
        FileReader fileReader = new FileReader(htpasswdPath);
        BufferedReader reader = new BufferedReader(fileReader);
        String s = null;
        Map<String,String> map = new HashMap<>();
        while ((s = reader.readLine()) != null){
            String[] split = s.split(":");
            map.put(split[0],split[1]);
        }
        reader.close();
        fileReader.close();
        return map;

    }

    @Override
    public void save(String username, String pass) throws Exception {
        Map<String, String> passMap = this.getPassMap();
        String encode = Md5Encoder.encode(username,pass);
        passMap.put(username, encode.split(":")[1]);
        savePassMap(passMap);

    }

    private void savePassMap(Map<String, String> passMap) throws Exception {
        FileWriter fileWriter = new FileWriter(configService.getHtpasswdPath());
        BufferedWriter writer = new BufferedWriter(fileWriter);
        for (String key : passMap.keySet()) {
            String user = key + ":" + passMap.get(key);
            writer.write(user);
            writer.newLine();
            writer.flush();
        }
        writer.close();
        fileWriter.close();
    }
}
