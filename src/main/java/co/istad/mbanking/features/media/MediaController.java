package co.istad.mbanking.features.media;

import co.istad.mbanking.features.media.dto.MediaResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/medias")
@RequiredArgsConstructor
public class MediaController {

    private final MediaService mediaService;

    @PostMapping("/upload-single")
    MediaResponse uploadSingle(@RequestPart MultipartFile file) {
        return mediaService.uploadSingle(file, "IMAGE");
    }

}
