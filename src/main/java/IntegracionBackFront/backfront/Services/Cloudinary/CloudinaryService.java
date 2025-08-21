package IntegracionBackFront.backfront.Services.Cloudinary;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

@Service
public class CloudinaryService {
    //1.Constante para definir el tamazo maximo permitido para los archivos (5MB)
    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024;

    //2. Extensiones de archivo permitidas para subir a Cloudinary
    private static final String[] ALLOWED_EXTENSIONS = {".jpg", ".png", ".jpeg"};

    //3.Cliente de Cloudinary inyectado como dependencia
    private final Cloudinary cloudinary;

    public CloudinaryService(Cloudinary cloudinary) {
        this.cloudinary = cloudinary;
    }

    //Subir imagenes a Cloudinary
    public String uploadImage(MultipartFile file) throws IOException {
        validateImage(file);
        Map<?, ?> uploadResult = cloudinary.uploader()
                .upload(file.getBytes(), ObjectUtils.asMap(
                        "resource_type", "auto",
                        "quality", "auto:good"
                ));
        return (String) uploadResult.get("secure_url");
    }

    public String uploadImage(MultipartFile file, String folder) throws IOException{
        validateImage(file);
        String orifinalFilename = file.getOriginalFilename();
        String fileExtension = orifinalFilename.substring(orifinalFilename.lastIndexOf(".")).toLowerCase();
        String uniqueFilename = "img" + UUID.randomUUID() + fileExtension;

        Map<String, Object> options = ObjectUtils.asMap(
                "folder", folder,
                "public_id", uniqueFilename,
                "use_filename", false,
                "unique_filename", false,
                "overwwrite", false,
                "resource_type", "auto",
                "quality", "auto:good"
        );
        Map<?, ?> uploadResult = cloudinary.uploader().upload(file.getBytes(), options);
        return (String) uploadResult.get("secure_url");
    }

    private void validateImage(MultipartFile file) {
        //1. Verificar si el archivo esta vacio
        if (file.isEmpty()) throw new IllegalArgumentException("El archivo no puede estar vacio");
        //2. Verificar si el tamaño del archivo excede el limite permitido
        if (file.getSize() > MAX_FILE_SIZE) throw new IllegalArgumentException("El tamaño del archivo no puede exceder los 5MB");
        String originalFileName = file.getOriginalFilename();
        if (originalFileName == null) throw new IllegalArgumentException("Nombre de archivo no valido");
        String extension = originalFileName.substring(originalFileName.lastIndexOf(".")).toLowerCase();
        if (!Arrays.asList(ALLOWED_EXTENSIONS).contains(extension)) throw new IllegalArgumentException("Solo se permiten archivos jpg, jpeg o png");
        if (!file.getContentType().startsWith("image/")) throw new IllegalArgumentException("El archivo debe ser una imagen valida");
    }
}
