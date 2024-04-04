package co.istad.mbanking.base;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BasedResponse<T> {
    private T payload;
}
