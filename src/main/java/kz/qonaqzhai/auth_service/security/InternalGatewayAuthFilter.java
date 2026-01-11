package kz.qonaqzhai.auth_service.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kz.qonaqzhai.auth_service.config.InternalGatewayAuthProperties;
import org.springframework.http.HttpStatus;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

public class InternalGatewayAuthFilter extends OncePerRequestFilter {

    private final InternalGatewayAuthProperties props;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public InternalGatewayAuthFilter(InternalGatewayAuthProperties props) {
        this.props = props;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!props.isEnabled()) {
            return true;
        }
        String path = request.getRequestURI();
        for (String pattern : props.getExcludedPaths()) {
            if (pathMatcher.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String secret = props.getSecret();
        if (secret == null || secret.isBlank()) {
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.getWriter().write("Internal gateway auth secret is not configured");
            return;
        }

        String timestampHeader = request.getHeader(props.getTimestampHeader());
        String signatureHeader = request.getHeader(props.getSignatureHeader());

        if (timestampHeader == null || signatureHeader == null) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return;
        }

        long ts;
        try {
            ts = Long.parseLong(timestampHeader);
        } catch (NumberFormatException ex) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return;
        }

        long now = Instant.now().toEpochMilli();
        long skewMs = Math.abs(now - ts);
        if (skewMs > props.getMaxSkewSeconds() * 1000L) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return;
        }

        String canonical = buildCanonical(request, timestampHeader);
        String expected = sign(secret, canonical);

        if (!constantTimeEquals(expected, signatureHeader)) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String buildCanonical(HttpServletRequest request, String timestampHeader) {
        String method = request.getMethod();
        String uri = request.getRequestURI();
        String query = request.getQueryString();
        String fullPath = (query == null || query.isBlank()) ? uri : (uri + "?" + query);
        return method + "\n" + fullPath + "\n" + timestampHeader;
    }

    private String sign(String secret, String canonical) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] sig = mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(sig);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign internal request", e);
        }
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        byte[] ba = a.getBytes(StandardCharsets.UTF_8);
        byte[] bb = b.getBytes(StandardCharsets.UTF_8);
        if (ba.length != bb.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < ba.length; i++) {
            result |= ba[i] ^ bb[i];
        }
        return result == 0;
    }
}
