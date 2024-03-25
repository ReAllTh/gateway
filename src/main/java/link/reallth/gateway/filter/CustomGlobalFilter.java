package link.reallth.gateway.filter;

import link.reallth.api.service.RemoteService;
import lombok.extern.slf4j.Slf4j;
import org.apache.dubbo.config.annotation.DubboReference;
import org.jetbrains.annotations.NotNull;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@Slf4j
@Configuration
public class CustomGlobalFilter implements GlobalFilter {

    public static final String COLUMN_USER_ID = "user_id";
    @DubboReference
    private RemoteService remoteService;
    public static final String HEADER_ATTR_SIGN = "sign";
    public static final String HEADER_ATTR_NONCE = "nonce";
    public static final String HEADER_ATTR_ACCESS_KEY = "accessKey";
    public static final String HEADER_ATTR_INTERFACE_ID = "interface_id";
    private static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1", "192.124.3.12");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        // logging
        HttpHeaders headers = request.getHeaders();
        String source = Objects.requireNonNull(request.getRemoteAddress()).toString();
        String method = request.getMethod().toString();
        String logMsg = "\n" + request.getId() + ": " +
                method + " " +
                source +
                " ==> " +
                request.getLocalAddress() +
                "\n" +
                "params: " + request.getQueryParams() +
                "\n" +
                "headers: " + headers;
        log.info(logMsg);
        ServerHttpResponse response = exchange.getResponse();
        // access control
        if (!IP_WHITE_LIST.contains(source)) {
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }
        // user auth check
        String accessKey = headers.getFirst(HEADER_ATTR_ACCESS_KEY);
        String nonce = headers.getFirst(HEADER_ATTR_NONCE);
        String sign = headers.getFirst(HEADER_ATTR_SIGN);
        if (sign == null || !sign.equals(remoteService.getSign(accessKey, nonce))) {
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }
        // interface info check
        String interfaceId = headers.getFirst(HEADER_ATTR_INTERFACE_ID);
        if (!remoteService.checkInterface(interfaceId, method)) {
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }
        return handleResponse(exchange, chain, interfaceId, headers.getFirst(COLUMN_USER_ID));
    }

    /**
     * response handle
     *
     * @param exchange exchange
     * @param chain    chain
     * @return result
     */
    public Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain, String interfaceInfoId, String userId) {
        try {
            ServerHttpResponse response = exchange.getResponse();
            DataBufferFactory bufferFactory = response.bufferFactory();
            HttpStatus statusCode = (HttpStatus) response.getStatusCode();
            if (statusCode == HttpStatus.OK) {
                // decorate response
                ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(response) {
                    @NotNull
                    @Override
                    public Mono<Void> writeWith(@NotNull Publisher<? extends DataBuffer> body) {
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                            return super.writeWith(
                                    fluxBody.map(dataBuffer -> {
                                        // count
                                        try {
                                            remoteService.count(interfaceInfoId, userId);
                                        } catch (Exception e) {
                                            log.error("count error", e);
                                        }
                                        // read response
                                        byte[] content = new byte[dataBuffer.readableByteCount()];
                                        dataBuffer.read(content);
                                        // release buffer
                                        DataBufferUtils.release(dataBuffer);
                                        // logging
                                        String data = new String(content, StandardCharsets.UTF_8); //data
                                        log.info("response result: " + data);
                                        return bufferFactory.wrap(content);
                                    })
                            );
                        } else
                            log.error("\n " + exchange.getRequest().getId() + " response error with code " + statusCode);
                        return super.writeWith(body);
                    }
                };
                // set decorated response as new response
                return chain.filter(exchange.mutate().response(decoratedResponse).build());
            }
            return chain.filter(exchange);
        } catch (Exception e) {
            log.error("gateway process error" + e);
            return chain.filter(exchange);
        }
    }
}