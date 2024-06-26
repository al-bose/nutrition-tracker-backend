package com.nutritiontracker.backend.security.services;

import java.util.Collection;
import java.util.Objects;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import com.nutritiontracker.backend.models.User;
import com.fasterxml.jackson.annotation.JsonIgnore;

public class UserDetailsImpl implements UserDetails {
    private static final long serialVersionUID = 1L;
  
    private Long id;
  
    private String username;
  
    private String email;
  
    @JsonIgnore
    private String password;

    private String firstName;

    private String lastName;
  
    public UserDetailsImpl(Long id, String username, String email, String password, String firstName, String lastName) {
      this.id = id;
      this.username = username;
      this.email = email;
      this.password = password;
      this.firstName = firstName;
      this.lastName = lastName;
    }
  
    public static UserDetailsImpl build(User user) {
  
      return new UserDetailsImpl(user.getId(), 
                                 user.getUsername(), 
                                 user.getEmail(),
                                 user.getPassword(),
                                 user.getFirstName(),
                                 user.getLastName());
    }
  
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
      return null;
    }
  
    public Long getId() {
      return id;
    }
  
    public String getEmail() {
      return email;
    }
  
    @Override
    public String getPassword() {
      return password;
    }
  
    @Override
    public String getUsername() {
      return username;
    }
  
    @Override
    public boolean isAccountNonExpired() {
      return true;
    }
  
    @Override
    public boolean isAccountNonLocked() {
      return true;
    }
  
    @Override
    public boolean isCredentialsNonExpired() {
      return true;
    }
  
    @Override
    public boolean isEnabled() {
      return true;
    }
  
    @Override
    public boolean equals(Object o) {
      if (this == o)
        return true;
      if (o == null || getClass() != o.getClass())
        return false;
      UserDetailsImpl user = (UserDetailsImpl) o;
      return Objects.equals(id, user.id);
    }

    public String getFirstName()
    {
      return this.firstName;
    }

    public String getLastName()
    {
      return this.lastName;
    }
  }
