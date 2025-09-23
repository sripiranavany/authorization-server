package com.sripiranavan.authorization_server.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@Component
public class AuditLoggingInterceptor implements HandlerInterceptor {

    private static final Logger auditLogger = LoggerFactory.getLogger("AUDIT");

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // Log incoming request
        logRequest(request);
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        // Log outgoing response
        logResponse(request, response, ex);
    }

    private void logRequest(HttpServletRequest request) {
        try {
            Map<String, Object> requestLog = new HashMap<>();
            requestLog.put("type", "REQUEST");
            requestLog.put("timestamp", System.currentTimeMillis());
            requestLog.put("method", request.getMethod());
            requestLog.put("uri", request.getRequestURI());
            requestLog.put("queryString", request.getQueryString());
            requestLog.put("remoteAddr", request.getRemoteAddr());
            requestLog.put("remoteHost", request.getRemoteHost());
            requestLog.put("userAgent", request.getHeader("User-Agent"));
            requestLog.put("contentType", request.getContentType());
            requestLog.put("contentLength", request.getContentLength());
            requestLog.put("sessionId", request.getSession(false) != null ? request.getSession().getId() : null);

            // Log headers (excluding sensitive ones)
            Map<String, String> headers = new HashMap<>();
            Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                if (!isSensitiveHeader(headerName)) {
                    headers.put(headerName, request.getHeader(headerName));
                } else {
                    headers.put(headerName, "***MASKED***");
                }
            }
            requestLog.put("headers", headers);

            // Log request parameters
            Map<String, String[]> parameters = request.getParameterMap();
            Map<String, Object> sanitizedParams = new HashMap<>();
            for (Map.Entry<String, String[]> entry : parameters.entrySet()) {
                String paramName = entry.getKey();
                if (isSensitiveParameter(paramName)) {
                    sanitizedParams.put(paramName, "***MASKED***");
                } else {
                    sanitizedParams.put(paramName, entry.getValue());
                }
            }
            requestLog.put("parameters", sanitizedParams);

            // Log request body for POST/PUT requests (if available and not too large)
            if (request instanceof ContentCachingRequestWrapper) {
                ContentCachingRequestWrapper wrapper = (ContentCachingRequestWrapper) request;
                byte[] content = wrapper.getContentAsByteArray();
                if (content.length > 0 && content.length < 10000) { // Log only if less than 10KB
                    String body = new String(content, wrapper.getCharacterEncoding());
                    if (containsSensitiveData(body)) {
                        requestLog.put("body", "***CONTAINS_SENSITIVE_DATA***");
                    } else {
                        requestLog.put("body", body);
                    }
                } else if (content.length >= 10000) {
                    requestLog.put("body", "***TOO_LARGE_" + content.length + "_BYTES***");
                }
            }

            auditLogger.info("REQUEST: {}", requestLog);

        } catch (Exception e) {
            auditLogger.error("Error logging request: {}", e.getMessage());
        }
    }

    private void logResponse(HttpServletRequest request, HttpServletResponse response, Exception ex) {
        try {
            Map<String, Object> responseLog = new HashMap<>();
            responseLog.put("type", "RESPONSE");
            responseLog.put("timestamp", System.currentTimeMillis());
            responseLog.put("method", request.getMethod());
            responseLog.put("uri", request.getRequestURI());
            responseLog.put("status", response.getStatus());
            responseLog.put("contentType", response.getContentType());
            responseLog.put("contentLength", response.getHeader("Content-Length"));

            // Log response headers (excluding sensitive ones)
            Map<String, String> headers = new HashMap<>();
            for (String headerName : response.getHeaderNames()) {
                if (!isSensitiveHeader(headerName)) {
                    headers.put(headerName, response.getHeader(headerName));
                } else {
                    headers.put(headerName, "***MASKED***");
                }
            }
            responseLog.put("headers", headers);

            // Log exception if present
            if (ex != null) {
                responseLog.put("exception", ex.getClass().getSimpleName());
                responseLog.put("exceptionMessage", ex.getMessage());
            }

            // Log response body (if available and not too large)
            if (response instanceof ContentCachingResponseWrapper) {
                ContentCachingResponseWrapper wrapper = (ContentCachingResponseWrapper) response;
                byte[] content = wrapper.getContentAsByteArray();
                if (content.length > 0 && content.length < 10000) { // Log only if less than 10KB
                    String body = new String(content, wrapper.getCharacterEncoding());
                    if (containsSensitiveData(body)) {
                        responseLog.put("body", "***CONTAINS_SENSITIVE_DATA***");
                    } else {
                        responseLog.put("body", body);
                    }
                } else if (content.length >= 10000) {
                    responseLog.put("body", "***TOO_LARGE_" + content.length + "_BYTES***");
                }
            }

            auditLogger.info("RESPONSE: {}", responseLog);

        } catch (Exception e) {
            auditLogger.error("Error logging response: {}", e.getMessage());
        }
    }

    private boolean isSensitiveHeader(String headerName) {
        String lowerHeaderName = headerName.toLowerCase();
        return lowerHeaderName.contains("authorization") ||
                lowerHeaderName.contains("cookie") ||
                lowerHeaderName.contains("token") ||
                lowerHeaderName.contains("password") ||
                lowerHeaderName.contains("secret");
    }

    private boolean isSensitiveParameter(String paramName) {
        String lowerParamName = paramName.toLowerCase();
        return lowerParamName.contains("password") ||
                lowerParamName.contains("secret") ||
                lowerParamName.contains("token") ||
                lowerParamName.contains("key") ||
                lowerParamName.contains("credential");
    }

    private boolean containsSensitiveData(String content) {
        if (content == null) return false;
        String lowerContent = content.toLowerCase();
        return lowerContent.contains("password") ||
                lowerContent.contains("secret") ||
                lowerContent.contains("token") ||
                lowerContent.contains("credential") ||
                lowerContent.contains("authorization");
    }
}
