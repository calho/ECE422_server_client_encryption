class Test
{
   public static void main(String[] args)
   {

      int[] testArray = {1,1};

      for(int i = 0; i < testArray.length; i++){
         System.out.println(testArray[i]);
      }
      	
      change(testArray);
      
      for(int i = 0; i < testArray.length; i++){
          System.out.println(testArray[i]);
       }
      
      
   }

   public static void change(int[] a)
   {

	   int y = a[0], z = a[1];

		y = y+1;
		z = z+2;

		a[0] = y;
		a[1] = z; 
   }
}