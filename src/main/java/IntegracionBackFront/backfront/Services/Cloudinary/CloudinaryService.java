package IntegracionBackFront.backfront.Services.Cloudinary;

import com.cloudinary.Cloudinary;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Arrays;

@Service
public class CloudinaryService {
    //1. Definir el tamaño de las imagenes en MB
    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024;
    //2.Definir las extensiones permitidas
    private static final String[] ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png"};
    //3. Atributo Cloudinary
    private final Cloudinary cloudinary;

    //Constructor para inyeccion de dependencias de Cloudinary
    public CloudinaryService(Cloudinary cloudinary) {
        this.cloudinary = cloudinary;
    }

    public String uploadImage(MultipartFile file) throws IOException {
        validateImage(file);
    }

    private void validateImage(MultipartFile file) {
        //1. Verficiar si el archivo esta vacio
        if (file.isEmpty()) {
            throw new IllegalArgumentException("El archivo esta vacio");
        }

        //2. Verficiar si el tamaño excede el limite permitido
        if (file.getSize() > MAX_FILE_SIZE){
            throw new IllegalArgumentException("El tamaño del archivo no debe ser mayor a 5MB");
        }

        //3. Verficiar el nombre original del archivo
        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null) {
            throw new IllegalArgumentException("Nombre de archivo invalido");
        }

        //4. Extraer y validar la extension del archivo
        String extension = originalFilename.substring(originalFilename.lastIndexOf(".")).toLowerCase();
        if (!Arrays.asList(ALLOWED_EXTENSIONS).contains(extension)) {
            throw new IllegalArgumentException("Solo se permiten archivos JPG, JPEG, PNG")
        }

        //5. Verificar que el tipo MIME sea una imagen
        if(!file.getContentType().startsWith("image/"));

    }
}
