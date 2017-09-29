package test;
import java.nio.charset.StandardCharsets;

import io.fd.vpp.jvpp.JVpp;
import io.fd.vpp.jvpp.JVppRegistry;
import io.fd.vpp.jvpp.JVppRegistryImpl;
import io.fd.vpp.jvpp.VppCallbackException;
import io.fd.vpp.jvpp.core.JVppCoreImpl;
import io.fd.vpp.jvpp.core.callback.SwInterfaceCallback;
import io.fd.vpp.jvpp.core.dto.SwInterfaceDetails;
import io.fd.vpp.jvpp.core.dto.SwInterfaceDump;

public class TestApi
{
	public static void main(String[] args) throws Exception
	{
		try
		(
			final JVppRegistry registry = new JVppRegistryImpl("TestApi");
			final JVpp jvpp = new JVppCoreImpl();
		)
		{
			registry.register(jvpp, new TestCallback());
			
			// Request interfaces dump
			SwInterfaceDump swInterfaceDumpRequest = new SwInterfaceDump();
			jvpp.send(swInterfaceDumpRequest);
			
			Thread.sleep(1000);
		}
		
		Thread.sleep(1000);
	}
	
	static class TestCallback implements SwInterfaceCallback
	{
		@Override
		public void onError(VppCallbackException ex)
		{
			System.out.println("Received onError exception: call="+ ex.getMethodName() +", context="+ ex.getCtxId() +", retval="+ ex.getErrorCode());
		}

		@Override
		public void onSwInterfaceDetails(SwInterfaceDetails reply)
		{
			System.out.println("Interface: "+ new String(reply.interfaceName, StandardCharsets.UTF_8));
		}
	}
}
