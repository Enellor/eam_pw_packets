<?php
/**
 * event codes and required configs for each eam object (module/page/layout)
 */
abstract class eam_interface
{
	/**
	 * @var array Events that may occur during executing
	 */
	protected static $event_codes = [];
	
	/**
	 * @return array static::event_codes
	 */
	final public static function getEvents(): array
	{
		return static::$event_codes;
	}
}

/**
 * Parent class for all modules (except some system modules)
 */
abstract class eam_module extends eam_interface
{
	//child class
}

//exceptions =======================================================
class eam_exception extends Exception 
{
	private $add_info = [];
	public function getAddInfo(): array
	{
		return $this->add_info;
	}
	
	public function __construct(int $code, \Throwable $previous = null, array $in_add_info)
	{
		$this->add_info = $in_add_info;
		
		global $module_name;
		parent::__construct($module_name::getEvents()[$code]['event_info'], $code, $previous);
	}
}