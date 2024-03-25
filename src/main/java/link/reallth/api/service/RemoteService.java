package link.reallth.api.service;

import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.Length;

/**
 * remote service
 *
 * @author ReAllTh
 */
public interface RemoteService {

    String INVALID_MSG_ID = "invalid id";
    String INVALID_MSG_KEY = "invalid key";

    /**
     * count interface invoke
     *
     * @param interfaceId target interface id
     * @param userId      user id
     * @return result
     */
    boolean count(
            @NotBlank
            @Length(min = 32, max = 32, message = INVALID_MSG_ID)
            String interfaceId,
            @NotBlank
            @Length(min = 32, max = 32, message = INVALID_MSG_ID)
            String userId
    );

    /**
     * return signed secret key
     *
     * @param accessKsy user access ksy
     * @param nonce     nonce
     * @return signed secret key
     */
    String getSign(
            @NotBlank
            @Length(min = 32, max = 32, message = INVALID_MSG_KEY)
            String accessKsy,
            @NotBlank
            String nonce
    );

    /**
     * check interface
     *
     * @param interfaceId interface id
     * @param method      method
     * @return result
     */
    boolean checkInterface(
            @NotBlank
            String interfaceId,
            @NotBlank
            String method
    );
}
