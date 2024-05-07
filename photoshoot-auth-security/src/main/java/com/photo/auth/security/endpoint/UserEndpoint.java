package com.photo.auth.security.endpoint;

import com.photo.master.data.dto.request.user.ChangesPasswordRequest;
import com.photo.master.data.enumeration.ApplicationConstant;
import com.photo.master.data.util.IResultDto;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RequestMapping(ApplicationConstant.ContextPath.API_AUTH)
//        consumes = MediaType.APPLICATION_JSON_VALUE,
//        produces = MediaType.APPLICATION_JSON_VALUE)
public interface UserEndpoint {

    @PatchMapping("/change-passwordd")
    IResultDto<Boolean> changesPassword(@RequestBody ChangesPasswordRequest request, Principal connectedUser, HttpServletRequest httpServletRequest);

}
