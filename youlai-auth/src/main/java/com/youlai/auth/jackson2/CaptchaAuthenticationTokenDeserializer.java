package com.youlai.auth.jackson2;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.youlai.auth.ext.captcha.CaptchaAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.List;

/**
 *
 * @see  org.springframework.security.jackson2.UsernamePasswordAuthenticationTokenDeserializer
 */
public class CaptchaAuthenticationTokenDeserializer extends JsonDeserializer<CaptchaAuthenticationToken> {

    private static final TypeReference<List<GrantedAuthority>> GRANTED_AUTHORITY_LIST = new TypeReference<List<GrantedAuthority>>() {
    };

    private static final TypeReference<Object> OBJECT = new TypeReference<Object>() {
    };

    @Override
    public CaptchaAuthenticationToken deserialize(JsonParser parser, DeserializationContext context) throws IOException {
        ObjectMapper mapper = (ObjectMapper) parser.getCodec();
        JsonNode jsonNode = mapper.readTree(parser);
        boolean authenticated = readJsonNode(jsonNode, "authenticated").asBoolean();
        JsonNode principalNode = readJsonNode(jsonNode, "principal");
        Object principal = getPrincipal(mapper, principalNode);
        JsonNode credentialsNode = readJsonNode(jsonNode, "credentials");
        JsonNode validateCodeNode = readJsonNode(jsonNode, "validateCode");
        JsonNode validateCodeCacheKeyNode = readJsonNode(jsonNode, "validateCodeCacheKey");
        String credentials = getJsonNodeText(credentialsNode);
        String validateCode = getJsonNodeText(validateCodeNode);
        String validateCodeCacheKey = getJsonNodeText(validateCodeCacheKeyNode);
        List<GrantedAuthority> authorities = mapper.readValue(readJsonNode(jsonNode, "authorities").traverse(mapper),
                GRANTED_AUTHORITY_LIST);
        CaptchaAuthenticationToken token = (!authenticated)
                ? new CaptchaAuthenticationToken(principal, credentials,validateCode,validateCodeCacheKey)
                : new CaptchaAuthenticationToken(principal, credentials, authorities);
        JsonNode detailsNode = readJsonNode(jsonNode, "details");
        if (detailsNode.isNull() || detailsNode.isMissingNode()) {
            token.setDetails(null);
        }
        else {
            Object details = mapper.readValue(detailsNode.toString(), OBJECT);
            token.setDetails(details);
        }
        return token;
    }

    private String getJsonNodeText(JsonNode jsonNode) {
        if (jsonNode.isNull() || jsonNode.isMissingNode()) {
            return null;
        }
        return jsonNode.asText();
    }

    private Object getPrincipal(ObjectMapper mapper, JsonNode principalNode)
            throws IOException {
        if (principalNode.isObject()) {
            return mapper.readValue(principalNode.traverse(mapper), Object.class);
        }
        return principalNode.asText();
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }

}
