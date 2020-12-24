package org.sid.securityservice.sec.service;

import org.sid.securityservice.serc.entities.AppRole;
import org.sid.securityservice.serc.entities.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username,String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUsers();
}
