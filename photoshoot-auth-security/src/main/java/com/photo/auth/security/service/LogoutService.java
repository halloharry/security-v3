package com.photo.auth.security.service;

import com.photo.master.data.dao.IAuthTokenDao;
import com.photo.master.data.util.IResultDto;
import com.photo.master.data.util.core.APIResponseBuilder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService {

    private final IAuthTokenDao authTokenDao;

//    @Override
    public IResultDto<Boolean> logout(HttpServletRequest request, HttpServletResponse response) {

        final String authHeader = request.getHeader("Authorization");
        final String jwtToken;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return APIResponseBuilder.internalServerError(false, null, "Logout failed. " + response,
                    request
            );
        }
        jwtToken = authHeader.substring(7); // 7 is after "BEARER "
        var storedToken = authTokenDao.findByToken(jwtToken).orElse(null);
        if (storedToken != null) {
            storedToken.setRevoked(true);
            storedToken.setExpired(true);
            authTokenDao.save(storedToken);
        }
        return APIResponseBuilder.ok(true);
    }
}
