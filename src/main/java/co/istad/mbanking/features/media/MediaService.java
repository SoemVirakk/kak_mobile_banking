package co.istad.mbanking.features.media;

import co.istad.mbanking.features.media.dto.MediaResponse;
import org.springframework.web.multipart.MultipartFile;

public interface MediaService {

    MediaResponse uploadSingle(MultipartFile file, String folderName);

}
