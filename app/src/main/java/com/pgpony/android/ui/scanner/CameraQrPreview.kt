package com.pgpony.android.ui.scanner

import android.graphics.Matrix
import android.util.Size
import android.view.MotionEvent
import android.view.View
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.FocusMeteringAction
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.UseCaseGroup
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.camera.view.TransformExperimental
import androidx.camera.view.transform.CoordinateTransform
import androidx.camera.view.transform.ImageProxyTransformFactory
import androidx.camera.view.transform.OutputTransform
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.Observer
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.pgpony.android.qr.*
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

@androidx.annotation.OptIn(markerClass = [TransformExperimental::class])
private data class PreviewMapping(val output: OutputTransform, val rectangle: PreviewRectangle)

/** CameraX and PreviewView share a viewport so ROI coordinates include display fill cropping. */
@androidx.annotation.OptIn(markerClass = [TransformExperimental::class])
@Composable
internal fun CameraQrPreview(
    session: QrScanSession,
    onQRDetected: (String, Long, () -> Unit) -> Unit,
    metrics: QrScanMetrics = QrScanMetrics.None,
    enableRegion: Boolean = true,
    retryToken: Int = 0,
    onCameraError: () -> Unit = {}
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val configuration = LocalConfiguration.current
    val latestCallback by rememberUpdatedState(onQRDetected)
    val latestCameraError by rememberUpdatedState(onCameraError)
    val viewfinderPixels = with(LocalDensity.current) { 250.dp.toPx() }
    val view = remember(context) {
        PreviewView(context).apply {
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
    }

    DisposableEffect(view, lifecycleOwner, configuration.orientation, viewfinderPixels, enableRegion, retryToken) {
        var provider: ProcessCameraProvider? = null
        var camera: Camera? = null
        val binding = ScannerCameraBinding { session.pause(); latestCameraError() }
        val mainExecutor = ContextCompat.getMainExecutor(context)
        val executor = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable,"pgpony-qr-analyzer")
        }
        val previewMapping = AtomicReference<PreviewMapping?>(null)
        val decoder = QrFrameDecoder(metrics=metrics,sessionId=session.id)
        val imageTransforms = ImageProxyTransformFactory()
        val transformMatrix = Matrix()
        val matrixValues = FloatArray(9)
        val rotation = view.display?.rotation ?: android.view.Surface.ROTATION_0
        val preview = Preview.Builder().setTargetRotation(rotation).build().also {
            it.surfaceProvider = view.surfaceProvider
        }
        val analysis = ImageAnalysis.Builder()
            .setTargetRotation(rotation)
            .setResolutionSelector(ResolutionSelector.Builder().setResolutionStrategy(
                ResolutionStrategy(Size(1280,720),ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER)
            ).build())
            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
            .build()

        fun refreshMapping() {
            val output = view.outputTransform
            previewMapping.set(if(output == null || view.width <= 0 || view.height <= 0) null else {
                val half = minOf(viewfinderPixels,view.width.toFloat(),view.height.toFloat())/2
                PreviewMapping(output,
                    PreviewRectangle(view.width/2f-half,view.height/2f-half,
                        view.width/2f+half,view.height/2f+half))
            })
        }
        fun bindWhenReady() {
            binding.bindWhenReady {
                if(view.width == 0 || view.height == 0) return@bindWhenReady false
                val cameraProvider = provider ?: return@bindWhenReady false
                val viewport = view.viewPort ?: return@bindWhenReady false
                val group = UseCaseGroup.Builder().setViewPort(viewport)
                    .addUseCase(preview).addUseCase(analysis).build()
                camera = cameraProvider.bindToLifecycle(lifecycleOwner,CameraSelector.DEFAULT_BACK_CAMERA,group)
                refreshMapping()
                true
            }
        }

        analysis.setAnalyzer(executor,CameraQrAnalyzer(session,mainExecutor,{ image ->
            val rect = image.cropRect
            val crop = PixelCrop(rect.left,rect.top,rect.right,rect.bottom)
            val mapping = if(enableRegion) previewMapping.get() else null
            val region = if(mapping == null) null else try {
                // Default factory settings map to raw buffer pixels, including cropRect offsets.
                CoordinateTransform(mapping.output,imageTransforms.getOutputTransform(image))
                    .transform(transformMatrix)
                transformMatrix.getValues(matrixValues)
                ScannerRegionMapper.map(mapping.rectangle,matrixValues,crop)
            } catch (_: RuntimeException) { null }
            val plane = image.planes.firstOrNull()
            if(plane == null) null else decoder.decode(plane.buffer,image.width,image.height,
                plane.rowStride,plane.pixelStride,crop,image.imageInfo.rotationDegrees,region)
        }) { text,token ->
            latestCallback(text,token,decoder::markProgress)
        })

        val lifecycleObserver = LifecycleEventObserver { _,event ->
            when(event) {
                Lifecycle.Event.ON_RESUME -> session.resume()
                Lifecycle.Event.ON_PAUSE -> { session.pause(); previewMapping.set(null) }
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(lifecycleObserver)
        if(lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) session.resume()
        val layoutListener = View.OnLayoutChangeListener { _,_,_,_,_,_,_,_,_ ->
            refreshMapping()
            bindWhenReady()
        }
        view.addOnLayoutChangeListener(layoutListener)
        val streamObserver = Observer<PreviewView.StreamState> { state ->
            if(state == PreviewView.StreamState.STREAMING) refreshMapping()
            else previewMapping.set(null)
        }
        view.previewStreamState.observe(lifecycleOwner,streamObserver)
        view.setOnTouchListener { touched,event ->
            if(event.action == MotionEvent.ACTION_UP) {
                touched.performClick()
                val activeCamera = camera
                if(activeCamera != null) {
                    val point = view.meteringPointFactory.createPoint(event.x,event.y)
                    val action = FocusMeteringAction.Builder(point,FocusMeteringAction.FLAG_AF or FocusMeteringAction.FLAG_AE)
                        .setAutoCancelDuration(3,TimeUnit.SECONDS).build()
                    try {
                        if(activeCamera.cameraInfo.isFocusMeteringSupported(action))
                            activeCamera.cameraControl.startFocusAndMetering(action)
                    } catch (_: RuntimeException) { /* Scanning continues if focus is unavailable. */ }
                }
            }
            true
        }
        val future = ProcessCameraProvider.getInstance(context)
        future.addListener({
            binding.providerReady { provider = future.get(); bindWhenReady() }
        },mainExecutor)
        metrics.milestone(session.id,ScanMilestone.READY,System.nanoTime())

        onDispose {
            binding.close {
                session.pause()
                previewMapping.set(null)
                lifecycleOwner.lifecycle.removeObserver(lifecycleObserver)
                view.removeOnLayoutChangeListener(layoutListener)
                view.previewStreamState.removeObserver(streamObserver)
                view.setOnTouchListener(null)
                try {
                    analysis.clearAnalyzer()
                    provider?.unbind(preview,analysis)
                } finally { executor.shutdown() }
            }
        }
    }
    AndroidView(factory={view},modifier=Modifier.fillMaxSize())
}
