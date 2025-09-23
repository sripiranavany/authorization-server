package com.sripiranavan.authorization_server.model;

import java.util.List;

public class UsersConfiguration {
    private List<UserConfig> users;

    public UsersConfiguration() {}

    public List<UserConfig> getUsers() {
        return users;
    }

    public void setUsers(List<UserConfig> users) {
        this.users = users;
    }
}
