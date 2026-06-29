package io.github.hectorvent.floci.core.common;

import io.quarkus.runtime.annotations.RegisterForReflection;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.ParserPoolImpl;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.directive.Break;
import org.apache.velocity.runtime.directive.Define;
import org.apache.velocity.runtime.directive.Evaluate;
import org.apache.velocity.runtime.directive.Foreach;
import org.apache.velocity.runtime.directive.Include;
import org.apache.velocity.runtime.directive.Macro;
import org.apache.velocity.runtime.directive.Parse;
import org.apache.velocity.runtime.directive.Stop;
import org.apache.velocity.runtime.parser.StandardParser;
import org.apache.velocity.runtime.resource.ResourceCacheImpl;
import org.apache.velocity.runtime.resource.ResourceManagerImpl;
import org.apache.velocity.runtime.resource.loader.StringResourceLoader;
import org.apache.velocity.runtime.resource.util.StringResourceRepositoryImpl;
import org.apache.velocity.util.introspection.SecureIntrospectorImpl;
import org.apache.velocity.util.introspection.SecureUberspector;
import org.apache.velocity.util.introspection.TypeConversionHandlerImpl;

import java.util.function.Consumer;

/**
 * Builds Velocity engines for API Gateway and AppSync VTL with CTF sandboxing:
 * {@link SecureUberspector}, string-only resource loaders, and restrict lists from
 * bundled {@code velocity.properties}.
 */
@RegisterForReflection(targets = {
        SecureUberspector.class,
        SecureIntrospectorImpl.class,
        TypeConversionHandlerImpl.class,
        ResourceManagerImpl.class,
        ResourceCacheImpl.class,
        ParserPoolImpl.class,
        StringResourceLoader.class,
        StringResourceRepositoryImpl.class,
        Foreach.class,
        Include.class,
        Parse.class,
        Macro.class,
        Evaluate.class,
        Break.class,
        Define.class,
        Stop.class,
        StandardParser.class,
})
public final class CtfVelocityEngineFactory {

    private static final String SECURE_UBERSPECTOR =
            "org.apache.velocity.util.introspection.SecureUberspector";
    private static final String STRING_RESOURCE_LOADER =
            "org.apache.velocity.runtime.resource.loader.StringResourceLoader";

    private CtfVelocityEngineFactory() {}

    public static VelocityEngine create(String runtimeLogName) {
        return create(runtimeLogName, null);
    }

    public static VelocityEngine create(String runtimeLogName, Consumer<VelocityEngine> customizer) {
        VelocityEngine engine = new VelocityEngine();
        engine.setProperty(RuntimeConstants.UBERSPECT_CLASSNAME, SECURE_UBERSPECTOR);
        engine.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8");
        engine.setProperty(RuntimeConstants.RUNTIME_LOG_NAME, runtimeLogName);
        engine.setProperty(RuntimeConstants.RESOURCE_LOADERS, "string");
        engine.setProperty("resource.loader.string.class", STRING_RESOURCE_LOADER);
        if (customizer != null) {
            customizer.accept(engine);
        }
        engine.init();
        return engine;
    }
}
