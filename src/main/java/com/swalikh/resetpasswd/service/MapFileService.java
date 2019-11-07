package com.swalikh.resetpasswd.service;

import java.util.Map;

public interface MapFileService {


    Map<String,String> getPassMap() throws Exception;

    void save(String username, String pass) throws Exception;
}
