# Sprawozdanie

Informatyka Techinczna, Studia niestacjonarne

## Cel ćwiczenia

Celem ćwiczenia było stworzenie bezpiecznego komunikatora do przesyłania komunikatów między dwoma użytkownikami.

## Realizacja ćwiczenia

### Użyte narzędzia

Komunikator został stworzony w języku programowania Python. Opiera się na architekturze klient-serwer.

Do zapewnienia bepieczeństwa w przesyłaniu komunikatów zostały zastosowane odpowiednie biblioteki kryptograficzne:

```
cryptography.fernet
cryptography.hazmat.primitives.asymmetric.rsa
```

`fernet` został użyty do szyfrowania symetrycznego, natomiast `rsa` do szyfrowania asymetrycznego.

### Komunikacja

Komunikacja klienta z serwerem odbywa się za pomocą ustalonego protokołu. Najpierw klient wymienia z serwerem publiczny klucz asymetryczny a następnie serwer odsyła klientowi zaszyfrowany klucz symetryczny. Dodatkowo każdemu klientowi zostaje przydzielony sekretny `uuid` znany tylko serwerowi i klientowi, sprawdzany przy każdej wymianie wiadomości.

W momencie w którym klient chce się połączyć i wymienić wiadomości z innym klientem, musi uczynić to poprzez serwer, który pośredniczy w wymianie wiadomości. Serwer odszyfrowuje wiadomość od jednego klienta za pomocą przyporządkowanego do niego klucza i zaszyfrowuje ją kluczem drugiego klienta.

W momencie w którym klienci chcą się wymienić wiadomościami również wymieniają między sobą klucze publiczne i prywatne, nieznane serwerowi.

### Wnioski

System umożliwia bezpieczną wymianę informacji pomiędzy klientami do momentu, w którym nie zostanie zastosowany atak Man-In-The-Middle. W momencie tego ataku, jeśli zostanie podstawiony "fałszywy serwer", tak zmodyfikowany by podmieniał właściwe klucze wysyłane do poszczególnych klientów, jest możliwe pełne odszyfrowanie wszystkich informacji wymienianych pomiędzy klientami.

By pozbyć się tej wady należy zastosować pełną certyfikację SSL.
