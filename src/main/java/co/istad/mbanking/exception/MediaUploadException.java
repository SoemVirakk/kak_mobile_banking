package co.istad.mbanking.exception;

import co.istad.mbanking.base.BasedError;
import co.istad.mbanking.base.BasedErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

@RestControllerAdvice
@Slf4j
public class MediaUploadException {

    @Value("${spring.servlet.multipart.max-request-size}")
    private String maxSize;

    @ResponseStatus(HttpStatus.PAYLOAD_TOO_LARGE)
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    BasedErrorResponse handleMaxUploadSizeExceededException(MaxUploadSizeExceededException e) {

        BasedError<String> basedError = BasedError.<String>builder()
                .code(HttpStatus.PAYLOAD_TOO_LARGE.getReasonPhrase())
                .description("Media upload size maximum is " + maxSize)
                .build();

        return new BasedErrorResponse(basedError);
    }

}
