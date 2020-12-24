package org.sid.securityservice.sec.service;

import org.sid.securityservice.sec.repo.AppRoleRepository;
import org.sid.securityservice.sec.repo.AppUserRepository;
import org.sid.securityservice.serc.entities.AppRole;
import org.sid.securityservice.serc.entities.AppUser;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;

@Service
@Transactional
public class AccountServiceImpl implements AccountService {
    private AppUserRepository appUserRepository;
    private AppRoleRepository appRoleRepository;
    //private PasswordEncoder passwordEncoder;
    public AccountServiceImpl(AppUserRepository appUserRepository, AppRoleRepository appRoleRepository)
    {
        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;
        //this.passwordEncoder = passwordEncoder;
    }
    @Override
    public AppUser addNewUser(AppUser appUser) {
        String pw=appUser.getPassword();
        return appUserRepository.save(appUser);
    }
    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }
    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser=appUserRepository.findByUsername(username);
        AppRole appRole=appRoleRepository.findByRoleName(roleName);
        appUser.getAppRoles().add(appRole);
    }
    @Override
    public AppUser loadUserByUsername(String username) { return appUserRepository.findByUsername(username); }
    @Override
    public List<AppUser> listUsers() {
        return appUserRepository.findAll();
    }
}
