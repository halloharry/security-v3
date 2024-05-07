package com.photo.auth.security.endpoint.impl;

import com.photo.auth.security.endpoint.AuthenticationEndpoint;
import com.photo.auth.security.service.AuthenticationService;
import com.photo.master.data.dto.request.user.*;
import com.photo.master.data.dto.response.user.AuthenticationResponseDto;
import com.photo.master.data.dto.response.user.ResponseRegisterUserDto;
import com.photo.master.data.util.IResultDto;
import com.photo.master.data.util.core.APIResponseBuilder;
import com.photo.master.data.util.exception.security.DuplicateDataException;
import com.photo.master.data.util.exception.security.ServiceException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;

import java.io.IOException;
import java.util.Objects;

@RequiredArgsConstructor
@RestController
public class AuthenticationEndpointImpl implements AuthenticationEndpoint {

    private final AuthenticationService authenticationService;

    @Override
    public IResultDto<ResponseRegisterUserDto> register(RequestRegisterUserDto request, HttpServletRequest httpServletRequest) {
        try {
            return APIResponseBuilder.ok(authenticationService.registerUser(request));
        } catch (ServiceException e) {
            return APIResponseBuilder.internalServerError(null, e, "Registration failed. " + e.getMessage(),
                    httpServletRequest
            );
        } catch (HttpClientErrorException e) {
            return APIResponseBuilder.badRequest(null, e, e.getMessage(), httpServletRequest);
        } catch (DuplicateDataException e) {
            return APIResponseBuilder.conflict(null, e, e.getMessage(), httpServletRequest);
        }
    }

    @Override
    public IResultDto<AuthenticationResponseDto> authenticate(AuthenticationRequestDto request, HttpServletRequest httpServletRequest) {
        try {
            AuthenticationResponseDto response = authenticationService.authenticate(request);
            if (Objects.nonNull(response)){
                return APIResponseBuilder.ok(response);
            }
            return APIResponseBuilder.internalServerError(null, null, "Authentication failed there is no user found" , httpServletRequest);
        } catch (ServiceException e) {
            return APIResponseBuilder.internalServerError(null, e, "Authentication failed. " + e.getMessage(), httpServletRequest);
        }
    }

    @Override
    public IResultDto<AuthenticationResponseDto> refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            AuthenticationResponseDto authResponse = authenticationService.refreshToken(request, response);
            if (Objects.nonNull(authResponse)){
                return APIResponseBuilder.ok(authResponse);
            }
            return APIResponseBuilder.internalServerError(null, null, "Authentication failed there is no user found" , request);
        } catch (ServiceException e) {
            return APIResponseBuilder.internalServerError(null, e, "Authentication failed. " + e.getMessage(), request);
        }
    }

    @Override
    public IResultDto<AuthenticationResponseDto> verifyCode(VerificationRequestDto verificationRequestDto, HttpServletRequest httpServletRequest) {
        return null;
    }
}
