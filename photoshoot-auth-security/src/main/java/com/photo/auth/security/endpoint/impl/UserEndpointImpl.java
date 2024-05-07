package com.photo.auth.security.endpoint.impl;

import com.photo.auth.security.endpoint.UserEndpoint;
import com.photo.auth.security.service.AuthenticationService;
import com.photo.master.data.dto.request.user.ChangesPasswordRequest;
import com.photo.master.data.dto.response.user.AuthenticationResponseDto;
import com.photo.master.data.util.IResultDto;
import com.photo.master.data.util.core.APIResponseBuilder;
import com.photo.master.data.util.exception.security.ServiceException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Objects;

@RequiredArgsConstructor
@RestController
public class UserEndpointImpl implements UserEndpoint {

    private final AuthenticationService authenticationService;

    @Override
    public IResultDto<Boolean> changesPassword(ChangesPasswordRequest request, Principal connectedUser, HttpServletRequest httpServletRequest) {
        try {
            if (connectedUser == null) {
                return APIResponseBuilder.forbidden(null, new ServiceException("no connected user :" + null), "Authentication failed ! Token has expired", httpServletRequest);
            }
            Boolean response = authenticationService.changesPassword(request, connectedUser);
            if (response){
                return APIResponseBuilder.ok(true);
            }
            return APIResponseBuilder.internalServerError(null, null, "Password inputed doesn't match" , httpServletRequest);
        } catch (ServiceException e) {
            return APIResponseBuilder.internalServerError(null, e, "Authentication failed. " + e.getMessage(), httpServletRequest);
        }
    }
}
