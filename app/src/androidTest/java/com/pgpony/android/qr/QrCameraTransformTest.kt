package com.pgpony.android.qr

import android.graphics.Matrix
import android.graphics.Rect
import android.util.Size
import androidx.camera.core.ImageInfo
import androidx.camera.core.ImageProxy
import androidx.camera.view.TransformExperimental
import androidx.camera.view.transform.CoordinateTransform
import androidx.camera.view.transform.ImageProxyTransformFactory
import androidx.camera.view.transform.OutputTransform
import com.pgpony.android.ui.scanner.PreviewRectangle
import com.pgpony.android.ui.scanner.ScannerRegionMapper
import java.lang.reflect.Proxy
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

@androidx.annotation.OptIn(markerClass = [TransformExperimental::class])
class QrCameraTransformTest {
    @Test fun cameraXDefaultImageTransformRetainsRawCropOffsetsAcrossPreviewQuarterTurn() {
        val info = Proxy.newProxyInstance(ImageInfo::class.java.classLoader,arrayOf(ImageInfo::class.java)) {
            _,method,_ -> if(method.name == "getRotationDegrees") 90 else null
        } as ImageInfo
        val image = Proxy.newProxyInstance(ImageProxy::class.java.classLoader,arrayOf(ImageProxy::class.java)) {
            _,method,_ -> when(method.name) {
                "getWidth" -> 640
                "getHeight" -> 480
                "getCropRect" -> Rect(20,10,620,470)
                "getImageInfo" -> info
                else -> null
            }
        } as ImageProxy
        val previewMatrix = Matrix().apply {
            setValues(floatArrayOf(0f,-150f,150f,230f,0f,230f,0f,0f,1f))
        }
        val preview = OutputTransform(previewMatrix,Size(600,460))
        val imageTransform = ImageProxyTransformFactory().getOutputTransform(image)
        val actual = Matrix()
        CoordinateTransform(preview,imageTransform).transform(actual)
        val values = FloatArray(9)
        actual.getValues(values)
        val mapped = ScannerRegionMapper.map(
            PreviewRectangle(75f,115f,225f,345f),values,PixelCrop(20,10,620,470),0f)
        assertNotNull(mapped)
        // CameraX float round-off can add one pixel during conservative outward rounding.
        assertTrue(mapped!!.left in 169..170 && mapped.top in 124..125)
        assertTrue(mapped.right in 470..471 && mapped.bottom in 355..356)
    }
}
