using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Hotel.ATR.Portal.Models
{
    public interface IRepository
    {
       List<Product> Products();
    }
}
