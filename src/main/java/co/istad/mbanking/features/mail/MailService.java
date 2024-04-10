package co.istad.mbanking.features.mail;

import co.istad.mbanking.features.mail.dto.MailRequest;
import co.istad.mbanking.features.mail.dto.MailResponse;

public interface MailService {

    MailResponse send(MailRequest mailRequest);

}
